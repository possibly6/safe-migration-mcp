"""Config file inspection + diff + apply (YAML / JSON / .env)."""
from __future__ import annotations
import difflib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

from . import db as dbmod

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    import tomli as tomllib  # type: ignore


def _kind(path: str) -> str:
    p = path.lower()
    if p.endswith((".yaml", ".yml")): return "yaml"
    if p.endswith(".json"):           return "json"
    if p.endswith(".env") or Path(path).name in (".env", ".env.local", ".env.production"): return "env"
    if p.endswith(".prisma"):         return "prisma"
    if p.endswith(".toml"):           return "toml"
    return "text"


def inspect_config_file(path: str) -> dict[str, Any]:
    p = Path(path).expanduser()
    path_issue = validate_config_target(path, for_write=False)
    if path_issue:
        return {"error": path_issue}
    if not p.exists():
        return {"error": f"File not found: {path}"}
    if p.is_dir():
        return {"error": f"Path is a directory, not a file: {path}"}
    text = p.read_text(encoding="utf-8")
    kind = _kind(path)
    try:
        if kind == "yaml":
            data = yaml.safe_load(text) or {}
            return {"path": str(p), "kind": kind, "keys": _top_keys(data), "size": len(text), "parsed": True}
        if kind == "json":
            data = json.loads(text) if text.strip() else {}
            return {"path": str(p), "kind": kind, "keys": _top_keys(data), "size": len(text), "parsed": True}
        if kind == "toml":
            data = tomllib.loads(text) if text.strip() else {}
            return {"path": str(p), "kind": kind, "keys": _top_keys(data), "size": len(text), "parsed": True}
        if kind == "env":
            pairs = _parse_env(text)
            return {"path": str(p), "kind": kind, "keys": list(pairs.keys()), "size": len(text), "parsed": True}
        if kind == "prisma":
            parsed = dbmod.inspect_db(str(p))
            if "error" in parsed:
                return {"path": str(p), "kind": kind, "parsed": False, "error": parsed["error"]}
            return {
                "path": str(p),
                "kind": kind,
                "size": len(text),
                "parsed": True,
                "models": sorted((parsed.get("tables") or {}).keys()),
            }
        return {
            "path": str(p),
            "kind": kind,
            "size": len(text),
            "parsed": False,
            "preview": _safe_preview(text),
        }
    except Exception as e:
        return {"path": str(p), "kind": kind, "parsed": False, "error": f"parse failed: {e}"}


def _top_keys(obj: Any, prefix: str = "") -> list[str]:
    if not isinstance(obj, dict):
        return []
    out = []
    for k, v in obj.items():
        key = f"{prefix}{k}"
        out.append(key)
        if isinstance(v, dict):
            out.extend(_top_keys(v, prefix=key + "."))
    return out


def _parse_env(text: str) -> dict[str, str]:
    d: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        if value and value[0] in {'"', "'"} and value[-1:] == value[0]:
            parsed = value[1:-1]
        else:
            parsed = re.sub(r"\s+#.*$", "", value).strip()
        d[key] = parsed
    return d


def diff_config(path: str, new_content: str) -> dict[str, Any]:
    """Return a unified diff, key-level adds/removes/changes, and risk flags."""
    p = Path(path).expanduser()
    old = p.read_text(encoding="utf-8") if p.exists() and p.is_file() else ""
    udiff = "".join(difflib.unified_diff(
        old.splitlines(keepends=True),
        new_content.splitlines(keepends=True),
        fromfile=f"a/{p.name}", tofile=f"b/{p.name}",
    ))
    kind = _kind(path)
    key_delta = _key_delta(old, new_content, kind)
    path_issue = validate_config_target(path, for_write=True)
    return {
        "path": str(p),
        "kind": kind,
        "unified_diff": _redact_diff(udiff),
        **key_delta,
        **({"path_issue": path_issue} if path_issue else {}),
    }


def _key_delta(old: str, new: str, kind: str) -> dict[str, Any]:
    try:
        o = _parse_structured(old, kind)
    except Exception as e:
        return {"old_parse_error": str(e)}
    try:
        n = _parse_structured(new, kind)
        if o is None or n is None:
            return {}
    except Exception as e:
        return {"parse_error": str(e)}
    old_flat = _flatten_mapping(o)
    new_flat = _flatten_mapping(n)
    ok, nk = set(old_flat), set(new_flat)
    return {
        "keys_added": sorted(nk - ok),
        "keys_removed": sorted(ok - nk),
        "keys_changed": sorted(k for k in ok & nk if old_flat[k] != new_flat[k]),
        "keys_kept": sorted(ok & nk),
    }


def apply_config(path: str, new_content: str) -> dict[str, Any]:
    """Atomically replace a file. Caller is expected to have snapshotted first."""
    path_issue = validate_config_target(path, for_write=True)
    if path_issue:
        return {"ok": False, "error": path_issue}
    p = Path(path).expanduser()
    try:
        _parse_structured(new_content, _kind(path))
    except Exception as e:
        return {"ok": False, "error": f"new content failed to parse: {e}"}
    p.parent.mkdir(parents=True, exist_ok=True)
    existed_before = p.exists()
    mode = p.stat().st_mode if existed_before else None
    fd, tmp_name = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(new_content)
            tmp.flush()
            os.fsync(tmp.fileno())
        if mode is not None:
            os.chmod(tmp_name, mode)
        else:
            os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, p)
        parent_fd = os.open(p.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except Exception:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    return {"ok": True, "path": str(p), "bytes": len(new_content), "created": not existed_before}


def revert_config(path: str, backup_path: str) -> dict[str, Any]:
    bp = Path(backup_path)
    if not bp.exists():
        return {"ok": False, "error": f"backup not found: {backup_path}"}
    result = apply_config(path, bp.read_text(encoding="utf-8"))
    if not result.get("ok"):
        return result
    return {"ok": True, "path": path, "restored_from": backup_path}


def validate_config_target(path: str, for_write: bool = False) -> str | None:
    p = Path(path).expanduser()
    if _has_symlink_component(p):
        return f"refusing to access symlinked config path: {path}"
    if p.exists():
        if p.is_dir():
            return f"path is a directory, not a file: {path}"
        if p.is_symlink():
            return f"refusing to write through symlinked config path: {path}"
    elif for_write and p.name in {"", ".", ".."}:
        return f"invalid target path: {path}"
    return None


def _parse_structured(text: str, kind: str) -> Any:
    if kind == "yaml":
        return yaml.safe_load(text) or {}
    if kind == "json":
        return json.loads(text) if text.strip() else {}
    if kind == "toml":
        return tomllib.loads(text) if text.strip() else {}
    if kind == "env":
        return _parse_env(text)
    if kind == "prisma":
        return {"models": re.findall(r"^\s*model\s+(\w+)\s*\{", text, flags=re.MULTILINE)}
    return None


def _flatten_mapping(obj: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            full_key = f"{prefix}{key}"
            if isinstance(value, dict):
                out.update(_flatten_mapping(value, prefix=full_key + "."))
            else:
                out[full_key] = value
        return out
    return {}


_SECRET_HINTS = re.compile(
    r"(password|passwd|pass|pw|secret|api[_-]?key|token|private[_-]?key|database[_-]?url|db[_-]?url|dsn|credentials?|conn(?:ection)?[_-]?string)",
    re.IGNORECASE,
)


def _redact_diff(udiff: str) -> str:
    redacted: list[str] = []
    for line in udiff.splitlines():
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            rendered = _redact_assignment(line[1:])
            if rendered is not None:
                redacted.append(f"{line[0]}{rendered}")
                continue
        redacted.append(line)
    return "\n".join(redacted) + ("\n" if udiff.endswith("\n") else "")


def _safe_preview(text: str) -> str:
    preview_lines: list[str] = []
    for line in text[:400].splitlines():
        rendered = _redact_assignment(line)
        if rendered is not None:
            preview_lines.append(rendered)
            continue
        preview_lines.append(line)
    return "\n".join(preview_lines)


def _redact_assignment(payload: str) -> str | None:
    if "=" in payload:
        key, _, value = payload.partition("=")
        delimiter = "="
    elif ":" in payload:
        key, _, value = payload.partition(":")
        delimiter = ": "
    else:
        return None
    normalized_key = key.strip().strip('"').strip("'")
    if _SECRET_HINTS.search(normalized_key) or _value_looks_secret(value):
        return f"{normalized_key}{delimiter}<redacted>"
    return None


def _value_looks_secret(value: str) -> bool:
    if re.search(r"[a-z][a-z0-9+\-.]*://[^/\s:@]+:[^@\s]+@", value, flags=re.IGNORECASE):
        return True
    if re.search(r"\b(eyJ[a-zA-Z0-9_-]{10,}|[A-Za-z0-9+/]{32,}={0,2})\b", value):
        return True
    return False


def _has_symlink_component(path: Path) -> bool:
    current = path
    while True:
        if current.is_symlink():
            return True
        if current.parent == current:
            return False
        if current.exists():
            current = current.parent
            continue
        parent = current.parent
        if parent == current:
            return False
        current = parent
