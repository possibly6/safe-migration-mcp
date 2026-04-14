"""Local state: proposals, snapshots, audit log."""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_SECRET_FIELD_NAMES = {"connection", "sql", "rollback", "new_content", "confirmation_token", "token"}
_INLINE_SECRET_KEYS = {"connection", "sql", "rollback", "new_content"}


class ProposalLockedError(RuntimeError):
    """Raised when a proposal lock cannot be acquired safely."""


def state_dir() -> Path:
    d = Path(os.environ.get("SAFE_MIGRATIONS_HOME", Path.home() / ".safe-migrations-mcp"))
    _ensure_private_dir(d)
    _ensure_private_dir(d / "proposals")
    _ensure_private_dir(d / "snapshots")
    _ensure_private_dir(d / "secrets")
    _ensure_private_dir(d / "locks")
    return d


def new_id(prefix: str = "p") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def save_proposal(proposal: dict[str, Any]) -> str:
    pid = proposal.get("id") or new_id()
    hydrated = dict(proposal)
    hydrated["id"] = pid
    hydrated["created_at"] = hydrated.get("created_at") or int(time.time())
    secret_payload = _extract_secret_payload(hydrated)
    public_payload = _sanitize_for_storage(hydrated)
    public_payload["secret_ref"] = str(_secret_path(pid))
    _atomic_write_text(_proposal_path(pid), json.dumps(public_payload, indent=2, default=str))
    _atomic_write_text(_secret_path(pid), json.dumps(secret_payload, indent=2, default=str))
    return pid


def load_proposal(pid: str) -> dict[str, Any] | None:
    path = _proposal_path(pid)
    if not path.exists():
        return None
    try:
        proposal = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    secret_path = Path(proposal.get("secret_ref", _secret_path(pid)))
    if secret_path.exists():
        try:
            proposal.update(json.loads(secret_path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            return None
    return proposal


def mark_proposal_applied(pid: str, result: dict[str, Any]) -> None:
    update_proposal(pid, {
        "applied": True,
        "applied_at": int(time.time()),
        "status": "applied",
        "result": result,
        "pending_confirmation": None,
    })


def update_proposal(pid: str, changes: dict[str, Any]) -> dict[str, Any] | None:
    with proposal_lock(pid):
        proposal = load_proposal(pid)
        if not proposal:
            return None
        proposal.update(changes)
        save_proposal(proposal)
        return proposal


def consume_pending_confirmation(pid: str, confirmation: str, expected_fingerprint: str, now_ts: int) -> dict[str, Any]:
    try:
        with proposal_lock(pid):
            proposal = load_proposal(pid)
            if not proposal:
                return {"ok": False, "error": f"proposal {pid} not found"}
            if proposal.get("applied"):
                return {"ok": False, "error": "proposal already applied", "applied_at": proposal.get("applied_at")}
            simulation = proposal.get("last_simulation")
            pending = proposal.get("pending_confirmation")
            if not simulation or not pending:
                return {"ok": False, "error": "proposal must be simulated immediately before apply"}
            if not simulation.get("appliable"):
                return {
                    "ok": False,
                    "error": "proposal is not safe to apply",
                    "apply_blockers": simulation.get("apply_blockers", []),
                }
            if pending.get("proposal_fingerprint") != expected_fingerprint:
                proposal["pending_confirmation"] = None
                save_proposal(proposal)
                return {"ok": False, "error": "proposal changed after simulation; run simulate_impact again"}
            if now_ts > int(pending.get("expires_at", 0)):
                proposal["pending_confirmation"] = None
                save_proposal(proposal)
                return {"ok": False, "error": "confirmation token expired; run simulate_impact again"}
            confirmation_hash = hashlib.sha256(confirmation.encode("utf-8")).hexdigest()
            if confirmation_hash != pending.get("token_hash"):
                proposal["pending_confirmation"] = None
                save_proposal(proposal)
                return {
                    "ok": False,
                    "error": "confirmation token mismatch",
                    "expected_format": "CONFIRM <proposal_id> <token>",
                }
            proposal["pending_confirmation"] = None
            save_proposal(proposal)
            return {"ok": True, "proposal": proposal}
    except ProposalLockedError as e:
        return {"ok": False, "error": str(e)}


def snapshot_file(path: str) -> str | None:
    """Copy a file into snapshots/ and return the backup path."""
    src = Path(path)
    if not src.exists() or not src.is_file():
        return None
    digest = _file_digest(src)[:10]
    dst = state_dir() / "snapshots" / f"{src.name}.{int(time.time())}.{digest}.bak"
    fd, tmp_name = tempfile.mkstemp(prefix=f".{src.name}.", suffix=".bak.tmp", dir=str(dst.parent))
    tmp_path = Path(tmp_name)
    try:
        with src.open("rb") as src_f, os.fdopen(fd, "wb") as tmp_f:
            shutil.copyfileobj(src_f, tmp_f, length=1024 * 1024)
            tmp_f.flush()
            os.fsync(tmp_f.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, dst)
        _fsync_dir(dst.parent)
    except Exception:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
        raise
    return str(dst)


def audit_log_path() -> Path:
    return state_dir() / "audit.jsonl"


def audit(entry: dict[str, Any]) -> None:
    entry = _sanitize_for_audit({"ts": int(time.time()), **entry})
    with audit_log_path().open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    os.chmod(audit_log_path(), 0o600)


def read_audit(limit: int = 100) -> list[dict[str, Any]]:
    p = audit_log_path()
    if not p.exists():
        return []
    safe_limit = max(1, min(int(limit), 1000))
    lines = p.read_text(encoding="utf-8").splitlines()[-safe_limit:]
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    return out


def purge_proposal_secret(pid: str) -> None:
    secret_path = _secret_path(pid)
    try:
        secret_path.unlink()
    except FileNotFoundError:
        pass


def cleanup_state(max_age_days: int = 30, keep_audit_entries: int = 100) -> dict[str, Any]:
    cutoff = time.time() - max(1, int(max_age_days)) * 86400
    removed = {"proposals": 0, "secrets": 0, "snapshots": 0}
    for directory, key in (
        (state_dir() / "proposals", "proposals"),
        (state_dir() / "secrets", "secrets"),
        (state_dir() / "snapshots", "snapshots"),
    ):
        for path in directory.iterdir():
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed[key] += 1
            except FileNotFoundError:
                continue
    _trim_audit_log(keep_audit_entries)
    return {
        "ok": True,
        "removed": removed,
        "kept_audit_entries": max(1, int(keep_audit_entries)),
    }


def _atomic_write_text(path: Path, content: str) -> None:
    _ensure_private_dir(path.parent)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    os.chmod(path, 0o600)


@contextmanager
def proposal_lock(pid: str):
    lock_path = state_dir() / "locks" / f"{pid}.lock"
    timeout_s = _lock_timeout_s()
    deadline = time.time() + timeout_s
    delay = 0.05
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.write(fd, json.dumps({"pid": os.getpid(), "ts": time.time()}).encode("utf-8"))
            break
        except FileExistsError:
            _clear_stale_lock(lock_path, timeout_s)
            if time.time() >= deadline:
                raise ProposalLockedError(f"proposal locked: {pid}")
            time.sleep(delay)
            delay = min(delay * 2, 0.5)
    try:
        yield
    finally:
        os.close(fd)
        try:
            os.unlink(lock_path)
        except FileNotFoundError:
            pass


def _proposal_path(pid: str) -> Path:
    return state_dir() / "proposals" / f"{pid}.json"


def _secret_path(pid: str) -> Path:
    return state_dir() / "secrets" / f"{pid}.json"


def _extract_secret_payload(proposal: dict[str, Any]) -> dict[str, Any]:
    return {key: proposal.get(key) for key in _INLINE_SECRET_KEYS if key in proposal}


def _sanitize_for_storage(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            if key in _INLINE_SECRET_KEYS:
                out[key] = _public_secret_summary(key, value)
            else:
                out[key] = _sanitize_for_storage(value)
        return out
    if isinstance(obj, list):
        return [_sanitize_for_storage(item) for item in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj


def _sanitize_for_audit(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            if key in _SECRET_FIELD_NAMES:
                out[key] = _public_secret_summary(key, value)
            else:
                out[key] = _sanitize_for_audit(value)
        return out
    if isinstance(obj, list):
        return [_sanitize_for_audit(item) for item in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj


def _public_secret_summary(key: str, value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    text = str(value)
    summary: dict[str, Any] = {
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "preview": _redact_string(text)[:160],
    }
    if key == "new_content":
        summary["bytes"] = len(text.encode("utf-8"))
    return summary


def _redact_string(text: str) -> str:
    redacted = _redact_uri_credentials(text)
    redacted = re.sub(
        r"(?i)\b(password|passwd|pass|secret|token|api[_-]?key|private[_-]?key|database[_-]?url|db[_-]?url|dsn|credentials?)\b\s*([:=])\s*([^\s]+)",
        lambda m: f"{m.group(1)}{m.group(2)}<redacted>",
        redacted,
    )
    redacted = re.sub(
        r"([a-z][a-z0-9+\-.]*://)([^/\s:@]+):([^@\s]+)@",
        lambda m: f"{m.group(1)}{m.group(2)}:<redacted>@",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted


def _redact_uri_credentials(text: str) -> str:
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if parts.scheme and parts.netloc and "@" in parts.netloc:
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        user = parts.username or "<redacted>"
        netloc = f"{user}:<redacted>@{host}{port}"
        return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return text


def _file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _trim_audit_log(keep_entries: int) -> None:
    keep = max(1, int(keep_entries))
    path = audit_log_path()
    if not path.exists():
        return
    lines = path.read_text(encoding="utf-8").splitlines()[-keep:]
    _atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _lock_timeout_s() -> float:
    raw = os.environ.get("SAFE_MIGRATIONS_LOCK_TIMEOUT_S", "15")
    try:
        return max(1.0, float(raw))
    except ValueError:
        return 15.0


def _clear_stale_lock(lock_path: Path, timeout_s: float) -> None:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8") or "{}")
        lock_ts = float(payload.get("ts", 0))
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        try:
            lock_ts = lock_path.stat().st_mtime
        except FileNotFoundError:
            return
    if time.time() - lock_ts > timeout_s:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass
