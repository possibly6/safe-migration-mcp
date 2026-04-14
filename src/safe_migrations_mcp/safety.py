"""Risk analysis for SQL statements and config diffs."""
from __future__ import annotations
import re
from typing import Any


# -------- SQL risk analysis --------
_DESTRUCTIVE = [
    (r"\bDROP\s+TABLE\b",         "critical", "Drops an entire table (all data lost)"),
    (r"\bDROP\s+DATABASE\b",      "critical", "Drops the entire database"),
    (r"\bDROP\s+SCHEMA\b",        "critical", "Drops a schema"),
    (r"\bDROP\s+COLUMN\b",        "high",     "Drops a column (data lost)"),
    (r"\bTRUNCATE\b",             "high",     "Empties a table"),
    (r"\bDELETE\s+FROM\b(?!.*\bWHERE\b)", "high", "DELETE without WHERE deletes every row"),
    (r"\bUPDATE\s+\w+\s+SET\b(?!.*\bWHERE\b)", "high", "UPDATE without WHERE rewrites every row"),
    (r"\bWHERE\s+(?:1\s*=\s*1|TRUE)\b", "medium", "Statement uses a tautological WHERE clause"),
    (r"\bDROP\s+INDEX\b",         "medium",   "Drops an index and may affect production performance"),
    (r"\bALTER\s+COLUMN\b.*\bTYPE\b", "medium", "Column type change may lose precision / fail on existing data"),
    (r"\bRENAME\s+TO\b",          "medium", "Rename breaks any code still referencing the old name"),
    (r"\bADD\s+COLUMN\b[^,;]*\bNOT\s+NULL\b(?![^,;]*\bDEFAULT\b)", "medium",
        "Adding NOT NULL column without DEFAULT fails if rows exist"),
    (r"\bGRANT\b|\bREVOKE\b",     "medium", "Changes DB permissions"),
]


def analyze_sql(sql: str) -> dict[str, Any]:
    from . import db as dbmod

    flags: list[dict[str, str]] = []
    sql_up = sql.upper()
    statements = dbmod.split_sql(sql)
    statement_count = len(statements)
    for stmt in statements or [sql]:
        stmt_up = stmt.upper()
        for pat, sev, msg in _DESTRUCTIVE:
            for m in re.finditer(pat, stmt_up, flags=re.DOTALL):
                flags.append({"severity": sev, "message": msg, "match": stmt[m.start():m.end()][:80]})
    if statement_count > 1:
        flags.append({
            "severity": "medium",
            "message": "Multiple SQL statements in one proposal increase blast radius and complicate rollback",
            "match": f"{statement_count} statements",
        })
    ddl = bool(re.search(r"\b(CREATE|ALTER|DROP|TRUNCATE)\b", sql_up))
    dml = bool(re.search(r"\b(INSERT|UPDATE|DELETE)\b", sql_up))
    max_sev = _max_sev([f["severity"] for f in flags]) or ("low" if dml else "none")
    return {
        "risk_level": max_sev,
        "is_ddl": ddl,
        "is_dml": dml,
        "statement_count": statement_count,
        "flags": flags,
        "destructive": max_sev in ("high", "critical"),
        "requires_confirmation": max_sev in ("medium", "high", "critical"),
    }


# -------- Config risk analysis --------
_SECRET_HINTS = re.compile(
    r"(password|passwd|pass|pw|secret|api[_-]?key|token|private[_-]?key|database[_-]?url|db[_-]?url|dsn|credentials?|conn(?:ection)?[_-]?string)",
    re.IGNORECASE,
)
_CRITICAL_KEY_HINTS = re.compile(
    r"(database|db|auth|secret|token|production|prod|migrations?)",
    re.IGNORECASE,
)


def analyze_config_diff(diff_result: dict[str, Any]) -> dict[str, Any]:
    flags: list[dict[str, str]] = []
    removed = diff_result.get("keys_removed", []) or []
    added   = diff_result.get("keys_added", [])   or []
    changed = diff_result.get("keys_changed", []) or []
    parse_error = diff_result.get("parse_error")
    path_issue = diff_result.get("path_issue")
    if parse_error:
        flags.append({"severity": "high", "message": "New config content failed to parse", "match": str(parse_error)})
    if path_issue:
        flags.append({"severity": "high", "message": path_issue, "match": diff_result.get("path", "")})
    for k in removed:
        sev = "high" if _CRITICAL_KEY_HINTS.search(k) else "medium"
        flags.append({"severity": sev, "message": f"Removes key '{k}'", "match": k})
    for k in added:
        if _SECRET_HINTS.search(k):
            flags.append({"severity": "medium", "message": f"Adds secret-looking key '{k}' — verify value is correct & not committed", "match": k})
    for k in changed:
        if _SECRET_HINTS.search(k):
            flags.append({"severity": "medium", "message": f"Changes secret-looking key '{k}'", "match": k})

    # Heuristics over the raw diff for value changes on secret-looking keys
    udiff = diff_result.get("unified_diff", "") or ""
    for line in udiff.splitlines():
        if line.startswith(("-", "+")) and not line.startswith(("---", "+++")):
            if _SECRET_HINTS.search(line):
                flags.append({
                    "severity": "medium",
                    "message": "Secret-looking value changed",
                    "match": _redact_line(line[:120]),
                })

    max_sev = _max_sev([f["severity"] for f in flags]) or "low"
    return {
        "risk_level": max_sev,
        "flags": flags,
        "destructive": bool(removed),
        "requires_confirmation": max_sev in ("medium", "high", "critical"),
    }


_SEV_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_sev(sevs: list[str]) -> str:
    if not sevs:
        return ""
    return max(sevs, key=lambda s: _SEV_ORDER.get(s, 0))


def _redact_line(line: str) -> str:
    if "=" in line:
        key, _, _ = line.partition("=")
        return f"{key}=<redacted>"
    if ":" in line:
        key, _, _ = line.partition(":")
        return f"{key}: <redacted>"
    return "<redacted>"
