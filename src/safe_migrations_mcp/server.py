"""FastMCP server exposing the Safe Migrations tools."""
from __future__ import annotations
import hashlib
import json
import secrets
import time
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - local test environments without MCP installed
    class FastMCP:  # type: ignore[override]
        def __init__(self, _: str):
            pass

        def tool(self) -> Any:
            def decorator(func: Any) -> Any:
                return func
            return decorator

        def run(self) -> None:
            raise RuntimeError("mcp package not installed; install safe-migrations-mcp dependencies to run the server")

from . import db as dbmod
from . import config as cfgmod
from . import migration as migmod
from . import safety
from . import state

mcp = FastMCP("safe-migrations-mcp")

_CONFIRM_PREFIX = "CONFIRM"
_CONFIRM_TTL_S = 15 * 60

_schema_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL = 60.0  # seconds


# ---------------- 1. inspect_schema ----------------
@mcp.tool()
def inspect_schema(connection: str, refresh: bool = False) -> dict[str, Any]:
    """Inspect a database or ORM schema file.

    connection examples:
      - sqlite:///path/to/app.db  OR  ./app.db
      - postgresql://user:pw@host/db
      - mysql://user:pw@host/db
      - ./prisma/schema.prisma
      - ./drizzle/schema.ts

    Results are cached locally for 60s unless refresh=True.
    """
    key = dbmod.cache_key(connection)
    now = time.time()
    if not refresh and key in _schema_cache:
        ts, cached = _schema_cache[key]
        if now - ts < _CACHE_TTL:
            return {"cached": True, "age_s": round(now - ts, 2), **cached}
    result = dbmod.inspect_db(connection)
    if "error" not in result:
        _schema_cache[key] = (now, result)
    return result


# ---------------- 2. inspect_config ----------------
@mcp.tool()
def inspect_config(path: str) -> dict[str, Any]:
    """Parse and summarize a config file (YAML/JSON/.env/Prisma/TOML/text)."""
    return cfgmod.inspect_config_file(path)


# ---------------- 3. propose_migration_or_edit ----------------
@mcp.tool()
def propose_migration_or_edit(
    kind: str,
    connection: str = "",
    request: str = "",
    sql: str = "",
    path: str = "",
    new_content: str = "",
) -> dict[str, Any]:
    """Propose a DB migration OR a config edit. Returns a proposal_id you pass to apply_change.

    Args:
      kind:        'db' or 'config'
      connection:  (db) connection string or schema-file path
      request:     (db) natural-language intent, e.g. "add column email of type TEXT not null default '' to users"
      sql:         (db) raw SQL — takes priority over `request`
      path:        (config) path to the file being edited
      new_content: (config) full new file contents

    Nothing is written. Call simulate_impact(proposal_id) next, then apply_change with the
    one-time confirmation_token returned by the simulation step.
    """
    if kind == "db":
        if not sql and not request:
            return {"error": "db proposals require either `sql` or `request`"}
        schema = dbmod.inspect_db(connection) if connection else None
        if connection and schema and "error" in schema:
            return {"error": schema["error"], "hint": schema.get("hint")}
        if sql:
            final_sql = sql
            rollback  = migmod.rollback_from_sql(sql, schema)
            summary   = "Raw SQL migration"
        else:
            r = migmod.nl_to_sql(request, schema=schema)
            if "error" in r:
                return r
            final_sql = r["sql"]; rollback = r["rollback"]; summary = r["summary"]
        proposal = {
            "kind": "db",
            "connection": connection,
            "request": request,
            "sql": final_sql,
            "rollback": rollback,
            "rollback_incomplete": rollback.lstrip().startswith("-- Rollback incomplete"),
            "summary": summary,
            "status": "proposed",
        }
        pid = state.save_proposal(proposal)
        return {
            "proposal_id": pid,
            "next_steps": [
                {"tool": "simulate_impact", "args": {"proposal_id": pid}},
                {"tool": "apply_change", "args": {"proposal_id": pid, "confirmation": "<confirmation_token from simulate_impact>"}},
            ],
            **_public_db_proposal_view(proposal),
        }

    if kind == "config":
        if not path or new_content == "":
            return {"error": "config proposals require both `path` and `new_content`"}
        diff = cfgmod.diff_config(path, new_content)
        proposal = {
            "kind": "config",
            "path": path,
            "new_content": new_content,
            "diff": diff,
            "rollback": "restore backup snapshot created at apply-time",
            "summary": f"Edit {path}",
            "status": "proposed",
        }
        pid = state.save_proposal(proposal)
        return {
            "proposal_id": pid,
            "next_steps": [
                {"tool": "simulate_impact", "args": {"proposal_id": pid}},
                {"tool": "apply_change", "args": {"proposal_id": pid, "confirmation": "<confirmation_token from simulate_impact>"}},
            ],
            "kind": "config",
            "path": path,
            "diff": diff,
            "summary": proposal["summary"],
            "status": "proposed",
        }

    return {"error": "kind must be 'db' or 'config'"}


# ---------------- 4. simulate_impact ----------------
@mcp.tool()
def simulate_impact(proposal_id: str) -> dict[str, Any]:
    """Dry-run a proposal. DB proposals execute inside a rolled-back transaction
    to surface errors and count affected rows. Config proposals show full diff + key delta.
    All results include risk flags and whether explicit confirmation is required.
    """
    p = state.load_proposal(proposal_id)
    if not p:
        return {"error": f"proposal {proposal_id} not found"}

    if p["kind"] == "db":
        risk = safety.analyze_sql(p["sql"])
        dry  = dbmod.execute_sql(p["connection"], p["sql"], dry_run=True) if p.get("connection") else {
            "ok": False, "error": "No connection: cannot dry-run; risk analysis only."
        }
        backup_plan = dbmod.backup_plan(p["connection"]) if p.get("connection") else {
            "kind": "unknown",
            "available": False,
            "path": None,
            "note": "No connection configured; cannot create a durable backup.",
        }
        blockers = _db_apply_blockers(risk, dry, backup_plan)
        response = {
            "proposal_id": proposal_id,
            "summary": p.get("summary"),
            "sql_preview": _preview_text(p["sql"]),
            "sql_sha256": _sha256_text(p["sql"]),
            "rollback_preview": _preview_text(p["rollback"]),
            "rollback_sha256": _sha256_text(p["rollback"]),
            "rollback_incomplete": p.get("rollback_incomplete", False),
            "dry_run": dry,
            "risk": risk,
            "backup": backup_plan,
            "confirmation_required": True,
            "appliable": not blockers,
            "apply_blockers": blockers,
        }
        return _record_simulation_and_build_response(proposal_id, p, response)

    if p["kind"] == "config":
        risk = safety.analyze_config_diff(p["diff"])
        blockers = []
        if p["diff"].get("parse_error"):
            blockers.append("new config content failed to parse")
        if p["diff"].get("path_issue"):
            blockers.append(p["diff"]["path_issue"])
        if risk.get("risk_level") in {"high", "critical"}:
            blockers.append(f"config change risk_level is {risk['risk_level']}; edit the file manually or reduce the blast radius before applying")
        response = {
            "proposal_id": proposal_id,
            "summary": p.get("summary"),
            "path": p["path"],
            "diff": p["diff"],
            "risk": risk,
            "confirmation_required": True,
            "appliable": not blockers,
            "apply_blockers": blockers,
        }
        return _record_simulation_and_build_response(proposal_id, p, response)

    return {"error": f"unknown proposal kind: {p['kind']}"}


# ---------------- 5. generate_rollback ----------------
@mcp.tool()
def generate_rollback(proposal_id: str = "", sql: str = "", connection: str = "") -> dict[str, Any]:
    """Produce exact undo SQL (for DB proposals) or a restore plan (for config).

    Either pass an existing proposal_id, or pass raw `sql` (+ optional `connection`
    for better schema-aware rollbacks).
    """
    if proposal_id:
        p = state.load_proposal(proposal_id)
        if not p:
            return {"error": f"proposal {proposal_id} not found"}
        if p["kind"] == "db":
            return {
                "proposal_id": proposal_id,
                "rollback": p["rollback"],
                "rollback_incomplete": p.get("rollback_incomplete", False),
            }
        return {
            "proposal_id": proposal_id,
            "note": "Config rollback is performed by restoring the snapshot created during apply_change.",
            "snapshot_will_be_at": "~/.safe-migrations-mcp/snapshots/",
        }
    if sql:
        schema = dbmod.inspect_db(connection) if connection else None
        if connection and schema and "error" in schema:
            return {"error": schema["error"], "hint": schema.get("hint")}
        rollback = migmod.rollback_from_sql(sql, schema)
        return {"rollback": rollback, "rollback_incomplete": rollback.lstrip().startswith("-- Rollback incomplete")}
    return {"error": "pass proposal_id or sql"}


# ---------------- 6. apply_change ----------------
@mcp.tool()
def apply_change(proposal_id: str, confirmation: str) -> dict[str, Any]:
    """Apply a proposal. Requires the one-time confirmation token from simulate_impact.

    Before writing, snapshots the affected file (configs) or the SQLite file,
    then executes inside a transaction where possible. Logs an audit entry.
    """
    loaded = state.load_proposal(proposal_id)
    if not loaded:
        return {"ok": False, "error": f"proposal {proposal_id} not found"}
    consumed = state.consume_pending_confirmation(
        proposal_id,
        confirmation,
        _proposal_fingerprint(loaded),
        int(time.time()),
    )
    if not consumed.get("ok"):
        return consumed
    p = consumed["proposal"]

    if p["kind"] == "db":
        risk = safety.analyze_sql(p["sql"])
        backup = dbmod.backup(p["connection"]) if p.get("connection") else {"available": False, "backup": None}
        if risk.get("destructive") and not backup.get("available"):
            blocked = _update_proposal_safely(proposal_id, {
                "status": "apply_blocked",
                "last_error": "backup unavailable",
                "pending_confirmation": None,
            })
            if blocked is not None:
                return blocked
            return {"ok": False, "error": "backup unavailable", "backup": backup}
        _evict_schema_cache(p.get("connection", ""))
        result = dbmod.execute_sql(p["connection"], p["sql"], dry_run=False)
        if result.get("ok"):
            apply_error = _mark_proposal_applied_safely(proposal_id, result)
            if apply_error is not None:
                return {**apply_error, "result": result, "backup": backup}
            state.audit({
                "event": "db.apply", "proposal_id": proposal_id,
                "connection": p["connection"], "sql": p["sql"],
                "rollback": p["rollback"], "backup": backup, "result": result,
            })
            return {"ok": True, "result": result, "backup": backup,
                    "rollback_sql_if_needed": p["rollback"]}
        update_error = _update_proposal_safely(proposal_id, {
            "status": "apply_failed",
            "last_error": result.get("error"),
            "pending_confirmation": None,
            "last_result": result,
        })
        if update_error is not None:
            return {**update_error, "result": result, "backup": backup}
        state.audit({
            "event": "db.apply_failed", "proposal_id": proposal_id,
            "connection": p["connection"], "sql": p["sql"],
            "rollback": p["rollback"], "backup": backup, "result": result,
        })
        return {"ok": False, "result": result, "backup": backup,
                "rollback_sql_if_needed": p["rollback"]}

    if p["kind"] == "config":
        existed_before = Path(p["path"]).expanduser().exists()
        backup_path = state.snapshot_file(p["path"])
        if existed_before and not backup_path:
            blocked = _update_proposal_safely(proposal_id, {
                "status": "apply_blocked",
                "last_error": "config snapshot unavailable",
            })
            if blocked is not None:
                return blocked
            return {"ok": False, "error": "config snapshot unavailable"}
        result = cfgmod.apply_config(p["path"], p["new_content"])
        if result.get("ok"):
            apply_error = _mark_proposal_applied_safely(proposal_id, {**result, "backup": backup_path})
            if apply_error is not None:
                return {**apply_error, "result": result, "backup": backup_path}
            state.purge_proposal_secret(proposal_id)
            state.audit({
                "event": "config.apply", "proposal_id": proposal_id,
                "path": p["path"], "backup": backup_path, "result": result,
            })
            return {"ok": True, "result": result, "backup": backup_path,
                    "revert_with": f"restore file from {backup_path}" if backup_path else "delete the file or restore from source control"}
        update_error = _update_proposal_safely(proposal_id, {
            "status": "apply_failed",
            "last_error": result.get("error"),
            "pending_confirmation": None,
            "last_result": result,
        })
        if update_error is not None:
            return {**update_error, "result": result, "backup": backup_path}
        state.audit({
            "event": "config.apply_failed", "proposal_id": proposal_id,
            "path": p["path"], "backup": backup_path, "result": result,
        })
        return {"ok": False, "result": result, "backup": backup_path}

    return {"ok": False, "error": f"unknown proposal kind: {p['kind']}"}


# ---------------- 7. get_change_history ----------------
@mcp.tool()
def get_change_history(limit: int = 50) -> dict[str, Any]:
    """Return the audit log of applied changes (most recent last)."""
    return {"entries": state.read_audit(limit)}


# ---------------- 8. cleanup_state ----------------
@mcp.tool()
def cleanup_state(max_age_days: int = 30) -> dict[str, Any]:
    """Prune old proposal metadata, secret payloads, and snapshots from local state."""
    return state.cleanup_state(max_age_days=max_age_days, keep_audit_entries=100)


def _record_simulation_and_build_response(
    proposal_id: str,
    proposal: dict[str, Any],
    response: dict[str, Any],
) -> dict[str, Any]:
    token = None
    pending_confirmation = None
    if response.get("appliable"):
        token = f"{_CONFIRM_PREFIX} {proposal_id} {secrets.token_urlsafe(12)}"
        pending_confirmation = {
            "token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "issued_at": int(time.time()),
            "expires_at": int(time.time()) + _CONFIRM_TTL_S,
            "proposal_fingerprint": _proposal_fingerprint(proposal),
        }
    simulation = {
        "at": int(time.time()),
        "appliable": response.get("appliable", False),
        "risk_level": (response.get("risk") or {}).get("risk_level"),
        "dry_run_ok": (response.get("dry_run") or {}).get("ok"),
        "apply_blockers": response.get("apply_blockers", []),
        "proposal_fingerprint": _proposal_fingerprint(proposal),
    }
    write_error = _update_proposal_safely(proposal_id, {
        "status": "simulated",
        "last_simulation": simulation,
        "pending_confirmation": pending_confirmation,
    })
    if write_error is not None:
        return write_error
    return {
        **response,
        "confirmation_token": token,
        "confirmation_token_expires_in_s": _CONFIRM_TTL_S if token else None,
    }


def _db_apply_blockers(risk: dict[str, Any], dry_run: dict[str, Any], backup_plan: dict[str, Any]) -> list[str]:
    blockers = []
    if dry_run.get("unsupported"):
        blockers.append(dry_run.get("error", "dry-run unsupported"))
    elif not dry_run.get("ok"):
        blockers.append(f"dry-run failed: {dry_run.get('error', 'unknown error')}")
    if risk.get("destructive") and not backup_plan.get("available"):
        blockers.append("destructive database change has no durable built-in backup for this connection")
    return blockers


def _proposal_fingerprint(proposal: dict[str, Any]) -> str:
    stable_fields = {
        key: value
        for key, value in proposal.items()
        if key not in {"created_at", "applied_at", "result", "last_result", "last_error", "pending_confirmation", "last_simulation", "status", "applied"}
    }
    payload = json.dumps(stable_fields, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def _evict_schema_cache(connection: str) -> None:
    if not connection:
        return
    prefix = dbmod.cache_prefix(connection)
    to_remove = [key for key in _schema_cache if key.startswith(prefix)]
    for key in to_remove:
        _schema_cache.pop(key, None)


def _update_proposal_safely(proposal_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
    try:
        proposal = state.update_proposal(proposal_id, changes)
    except state.ProposalLockedError as e:
        return {"ok": False, "error": str(e)}
    if proposal is None:
        return {"ok": False, "error": f"proposal {proposal_id} not found"}
    return None


def _mark_proposal_applied_safely(proposal_id: str, result: dict[str, Any]) -> dict[str, Any] | None:
    try:
        state.mark_proposal_applied(proposal_id, result)
    except state.ProposalLockedError as e:
        return {"ok": False, "error": str(e)}
    return None


def _public_db_proposal_view(proposal: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "db",
        "connection_preview": _redact_connection(proposal.get("connection", "")),
        "request": proposal.get("request", ""),
        "sql_preview": _preview_text(proposal.get("sql", "")),
        "sql_sha256": _sha256_text(proposal.get("sql", "")),
        "rollback_preview": _preview_text(proposal.get("rollback", "")),
        "rollback_sha256": _sha256_text(proposal.get("rollback", "")),
        "rollback_incomplete": proposal.get("rollback_incomplete", False),
        "summary": proposal.get("summary"),
        "status": proposal.get("status"),
    }


def _redact_connection(connection: str) -> str:
    if not connection:
        return ""
    return state._redact_string(connection)


def _preview_text(text: str, max_chars: int = 240) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
