"""Turn natural-language requests or raw SQL into a migration proposal with rollback.

Pattern-matches a small, high-confidence set of intents. For anything more
complex the caller should pass raw SQL via `sql=...`; we still compute a
best-effort rollback from the live schema.
"""
from __future__ import annotations
import re
from typing import Any

from . import db as dbmod


# ---------- NL → SQL ----------
_ADD_COL = re.compile(
    r"add\s+(?:a\s+)?column\s+(?P<col>\w+)\s+(?:of\s+type\s+|as\s+|:?\s*)(?P<type>\w+(?:\(\d+\))?)"
    r"(?P<nullable>\s+not\s+null)?"
    r"(?:\s+(?:with\s+)?default\s+(?P<default>[\w'\"-]+))?"
    r"\s+(?:to|on|in)\s+(?:table\s+)?(?P<table>\w+)",
    re.IGNORECASE,
)
_DROP_COL = re.compile(
    r"(?:drop|remove|delete)\s+(?:the\s+)?column\s+(?P<col>\w+)\s+(?:from|on|in)\s+(?:table\s+)?(?P<table>\w+)",
    re.IGNORECASE,
)
_RENAME_COL = re.compile(
    r"rename\s+(?:the\s+)?column\s+(?P<old>\w+)\s+(?:to|as)\s+(?P<new>\w+)\s+(?:on|in)\s+(?:table\s+)?(?P<table>\w+)",
    re.IGNORECASE,
)
_CREATE_INDEX = re.compile(
    r"(?:create|add)\s+(?:a\s+)?(?P<uniq>unique\s+)?index\s+on\s+(?P<table>\w+)\s*\(\s*(?P<cols>[\w\s,]+)\s*\)",
    re.IGNORECASE,
)
_DROP_TABLE = re.compile(r"(?:drop|delete)\s+(?:the\s+)?table\s+(?P<table>\w+)", re.IGNORECASE)


def nl_to_sql(text: str, schema: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return {'sql': ..., 'rollback': ..., 'summary': ...} or {'error': ...}."""
    t = text.strip()
    if not t:
        return {"error": "request cannot be empty"}

    m = _ADD_COL.search(t)
    if m:
        col, typ, table = m["col"], m["type"], m["table"]
        table_error = _validate_table_exists(schema, table)
        if table_error:
            return {"error": table_error}
        if _find_column(schema, table, col):
            return {"error": f"Column already exists: {table}.{col}"}
        not_null = " NOT NULL" if m["nullable"] else ""
        default  = f" DEFAULT {m['default']}" if m["default"] else ""
        sql      = f'ALTER TABLE "{table}" ADD COLUMN "{col}" {typ}{default}{not_null};'
        rollback = f'ALTER TABLE "{table}" DROP COLUMN "{col}";'
        return {"sql": sql, "rollback": rollback, "summary": f"Add {col}:{typ} to {table}"}

    m = _DROP_COL.search(t)
    if m:
        col, table = m["col"], m["table"]
        table_error = _validate_table_exists(schema, table)
        if table_error:
            return {"error": table_error}
        col_info = _find_column(schema, table, col) if schema else None
        if not col_info:
            return {"error": f"Column not found: {table}.{col}"}
        rollback = _incomplete_rollback(
            f"Dropping {table}.{col} loses column data.",
            f'Schema-only hint: ALTER TABLE "{table}" ADD COLUMN {_render_column_definition(col_info)};',
        )
        return {"sql": f'ALTER TABLE "{table}" DROP COLUMN "{col}";', "rollback": rollback,
                "summary": f"Drop {col} from {table}"}

    m = _RENAME_COL.search(t)
    if m:
        old, new, table = m["old"], m["new"], m["table"]
        table_error = _validate_table_exists(schema, table)
        if table_error:
            return {"error": table_error}
        if not _find_column(schema, table, old):
            return {"error": f"Column not found: {table}.{old}"}
        if _find_column(schema, table, new):
            return {"error": f"Target column already exists: {table}.{new}"}
        return {
            "sql":      f'ALTER TABLE "{table}" RENAME COLUMN "{old}" TO "{new}";',
            "rollback": f'ALTER TABLE "{table}" RENAME COLUMN "{new}" TO "{old}";',
            "summary":  f"Rename {table}.{old} -> {new}",
        }

    m = _CREATE_INDEX.search(t)
    if m:
        table = m["table"]
        cols = [c.strip() for c in m["cols"].split(",")]
        table_error = _validate_table_exists(schema, table)
        if table_error:
            return {"error": table_error}
        missing_cols = [c for c in cols if not _find_column(schema, table, c)] if schema else []
        if missing_cols:
            return {"error": f"Columns not found on {table}: {', '.join(missing_cols)}"}
        uniq = "UNIQUE " if m["uniq"] else ""
        iname = f"idx_{table}_{'_'.join(cols)}"
        qcols = ", ".join(f'"{c}"' for c in cols)
        return {
            "sql":      f'CREATE {uniq}INDEX "{iname}" ON "{table}" ({qcols});',
            "rollback": f'DROP INDEX "{iname}";',
            "summary":  f"Index on {table}({', '.join(cols)})",
        }

    m = _DROP_TABLE.search(t)
    if m:
        table = m["table"]
        table_error = _validate_table_exists(schema, table)
        if table_error:
            return {"error": table_error}
        create = _recreate_table_ddl(schema, table) if schema else None
        rollback = _incomplete_rollback(
            f"Dropping table {table} loses all row data.",
            f"Schema-only hint:\n{create}" if create else None,
        )
        return {"sql": f'DROP TABLE "{table}";', "rollback": rollback,
                "summary": f"Drop table {table}"}

    return {"error": "Could not parse intent. Pass raw SQL via `sql=...` instead.",
            "parseable_intents": [
                "add column <col> of type <TYPE> [not null] [default <V>] to <table>",
                "drop column <col> from <table>",
                "rename column <old> to <new> on <table>",
                "create [unique] index on <table>(col1, col2)",
                "drop table <table>",
            ]}


def _find_column(schema: dict[str, Any] | None, table: str, col: str) -> dict[str, Any] | None:
    if not schema: return None
    tbl = (schema.get("tables") or {}).get(table)
    if not tbl: return None
    for c in tbl.get("columns", []):
        if c["name"] == col:
            return c
    return None


def _recreate_table_ddl(schema: dict[str, Any] | None, table: str) -> str | None:
    if not schema: return None
    tbl = (schema.get("tables") or {}).get(table)
    if not tbl: return None
    parts = []
    for c in tbl.get("columns", []):
        parts.append(_render_column_definition(c))
    return f'CREATE TABLE "{table}" (\n  ' + ",\n  ".join(parts) + "\n);"


# ---------- Best-effort rollback from raw SQL ----------
_RB_ADD_COL    = re.compile(r'ALTER\s+TABLE\s+"?(\w+)"?\s+ADD\s+COLUMN\s+"?(\w+)"?', re.IGNORECASE)
_RB_DROP_COL   = re.compile(r'ALTER\s+TABLE\s+"?(\w+)"?\s+DROP\s+COLUMN\s+"?(\w+)"?', re.IGNORECASE)
_RB_RENAME_COL = re.compile(r'ALTER\s+TABLE\s+"?(\w+)"?\s+RENAME\s+COLUMN\s+"?(\w+)"?\s+TO\s+"?(\w+)"?', re.IGNORECASE)
_RB_CREATE_IDX = re.compile(r'CREATE\s+(?:UNIQUE\s+)?INDEX\s+"?(\w+)"?\s+ON', re.IGNORECASE)
_RB_DROP_IDX   = re.compile(r'DROP\s+INDEX\s+"?(\w+)"?', re.IGNORECASE)
_RB_CREATE_TBL = re.compile(r'CREATE\s+TABLE\s+"?(\w+)"?', re.IGNORECASE)
_RB_DROP_TBL   = re.compile(r'DROP\s+TABLE\s+"?(\w+)"?', re.IGNORECASE)


def rollback_from_sql(sql: str, schema: dict[str, Any] | None = None) -> str:
    lines = []
    for stmt in dbmod.split_sql(sql):
        rb = _single_rollback(stmt, schema)
        if rb:
            lines.append(rb if rb.rstrip().endswith(";") else rb + ";")
    # Rollbacks typically run in reverse order
    return "\n".join(reversed(lines)) if lines else "-- No automatic rollback could be generated."


def _single_rollback(stmt: str, schema: dict[str, Any] | None) -> str:
    m = _RB_ADD_COL.search(stmt)
    if m: return f'ALTER TABLE "{m.group(1)}" DROP COLUMN "{m.group(2)}"'
    m = _RB_DROP_COL.search(stmt)
    if m:
        col = _find_column(schema, m.group(1), m.group(2))
        if col:
            return _incomplete_rollback(
                f"Dropping {m.group(1)}.{m.group(2)} loses column data.",
                f'Schema-only hint: ALTER TABLE "{m.group(1)}" ADD COLUMN {_render_column_definition(col)}',
            )
        return _incomplete_rollback(f"Cannot rollback DROP COLUMN {m.group(1)}.{m.group(2)}")
    m = _RB_RENAME_COL.search(stmt)
    if m: return f'ALTER TABLE "{m.group(1)}" RENAME COLUMN "{m.group(3)}" TO "{m.group(2)}"'
    m = _RB_CREATE_IDX.search(stmt)
    if m: return f'DROP INDEX "{m.group(1)}"'
    m = _RB_DROP_IDX.search(stmt)
    if m: return f'-- Cannot rollback DROP INDEX "{m.group(1)}" without original definition'
    m = _RB_CREATE_TBL.search(stmt)
    if m: return f'DROP TABLE "{m.group(1)}"'
    m = _RB_DROP_TBL.search(stmt)
    if m:
        ddl = _recreate_table_ddl(schema, m.group(1))
        return _incomplete_rollback(
            f"Dropping table {m.group(1)} loses all row data.",
            f"Schema-only hint:\n{ddl.rstrip(';')}" if ddl else None,
        )
    if re.match(r'\s*(INSERT|UPDATE|DELETE|TRUNCATE)\b', stmt, re.IGNORECASE):
        return _incomplete_rollback("DML rollback requires a backup or snapshot; exact undo SQL is unavailable.")
    return ""


def _validate_table_exists(schema: dict[str, Any] | None, table: str) -> str | None:
    if schema is None:
        return None
    tables = schema.get("tables") or {}
    if table not in tables:
        return f"Table not found: {table}"
    return None


def _render_column_definition(col: dict[str, Any]) -> str:
    line = f'"{col["name"]}" {col["type"]}'
    if col.get("default") is not None:
        line += f" DEFAULT {col['default']}"
    if col.get("not_null"):
        line += " NOT NULL"
    if col.get("pk"):
        line += " PRIMARY KEY"
    return line


def _incomplete_rollback(reason: str, hint: str | None = None) -> str:
    lines = [f"-- Rollback incomplete: {reason}"]
    if hint:
        for line in hint.splitlines():
            lines.append(f"-- {line}")
    return "\n".join(lines)
