"""DB schema inspection. SQLite first-class; Postgres/MySQL via optional deps.
Also handles file-based ORM schemas (Prisma, Drizzle) by parsing the file.
"""
from __future__ import annotations
import re
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_MAX_STATEMENTS = 50


def _kind(conn: str) -> str:
    low = conn.lower()
    if low.endswith(".prisma") or "schema.prisma" in low:
        return "prisma"
    if low.endswith((".ts", ".js")) and ("drizzle" in low or "schema" in Path(low).stem):
        return "drizzle"
    if low.startswith("sqlite:") or low.endswith(".db") or low.endswith(".sqlite") or low.endswith(".sqlite3"):
        return "sqlite"
    if low.startswith(("postgres://", "postgresql://")):
        return "postgres"
    if low.startswith("mysql://"):
        return "mysql"
    if Path(conn).exists() and conn.endswith((".db", ".sqlite", ".sqlite3")):
        return "sqlite"
    return "unknown"


def _sqlite_path(conn: str) -> str:
    if conn.startswith("sqlite:///"):
        return conn[len("sqlite:///") :]
    if conn.startswith("sqlite://"):
        return conn[len("sqlite://") :]
    return conn


def cache_key(connection: str) -> str:
    kind = _kind(connection)
    if kind == "sqlite":
        path = Path(_sqlite_path(connection)).expanduser()
        return _path_cache_key(kind, path)
    if kind in {"prisma", "drizzle"}:
        return _path_cache_key(kind, Path(connection).expanduser())
    return f"{kind}:{connection}"


def cache_prefix(connection: str) -> str:
    kind = _kind(connection)
    if kind == "sqlite":
        return f"{kind}:{Path(_sqlite_path(connection)).expanduser().resolve()}"
    if kind in {"prisma", "drizzle"}:
        return f"{kind}:{Path(connection).expanduser().resolve()}"
    return f"{kind}:{connection}"


def split_sql(sql: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    in_single = False
    in_double = False
    in_backtick = False
    in_line_comment = False
    in_block_comment = False
    dollar_quote_tag = ""
    i = 0
    while i < len(sql):
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""
        if in_line_comment:
            buf.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            buf.append(ch)
            if ch == "*" and nxt == "/":
                buf.append(nxt)
                i += 2
                in_block_comment = False
                continue
            i += 1
            continue
        if dollar_quote_tag:
            buf.append(ch)
            if sql.startswith(dollar_quote_tag, i):
                if len(dollar_quote_tag) > 1:
                    buf.extend(list(sql[i + 1:i + len(dollar_quote_tag)]))
                i += len(dollar_quote_tag)
                dollar_quote_tag = ""
                continue
            i += 1
            continue
        if not in_single and not in_double and ch == "-" and nxt == "-":
            buf.extend([ch, nxt])
            i += 2
            in_line_comment = True
            continue
        if not in_single and not in_double and ch == "/" and nxt == "*":
            buf.extend([ch, nxt])
            i += 2
            in_block_comment = True
            continue
        if ch == "'" and not in_double:
            if in_single and nxt == "'":
                buf.extend([ch, nxt])
                i += 2
                continue
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue
        if ch == '"' and not in_single and not in_backtick:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue
        if ch == "`" and not in_single and not in_double:
            in_backtick = not in_backtick
            buf.append(ch)
            i += 1
            continue
        if ch == "$" and not in_single and not in_double and not in_backtick:
            tag_match = re.match(r"\$[A-Za-z_0-9]*\$", sql[i:])
            if tag_match:
                dollar_quote_tag = tag_match.group(0)
                buf.extend(list(dollar_quote_tag))
                i += len(dollar_quote_tag)
                continue
        if ch == ";" and not in_single and not in_double and not in_backtick:
            stmt = "".join(buf).strip()
            if stmt:
                statements.append(stmt)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


def inspect_db(connection: str) -> dict[str, Any]:
    k = _kind(connection)
    if k == "sqlite":
        return _inspect_sqlite(_sqlite_path(connection))
    if k == "postgres":
        return _inspect_postgres(connection)
    if k == "mysql":
        return _inspect_mysql(connection)
    if k == "prisma":
        return _parse_prisma(connection)
    if k == "drizzle":
        return _parse_drizzle(connection)
    return {"error": f"Unsupported connection: {connection}", "hint": "sqlite:///path.db | postgresql://... | mysql://... | schema.prisma"}


# ---------- SQLite ----------
def _inspect_sqlite(path: str) -> dict[str, Any]:
    db_path = Path(path).expanduser()
    if not db_path.exists():
        return {"error": f"SQLite file not found: {path}"}
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cur = con.cursor()
        cur.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view','index') AND name NOT LIKE 'sqlite_%'")
        objs = cur.fetchall()
        tables: dict[str, Any] = {}
        indexes: list[dict[str, Any]] = []
        for name, typ in objs:
            if typ == "table":
                escaped = _quote_sqlite_ident(name)
                cur.execute(f'PRAGMA table_info("{escaped}")')
                cols = [
                    {"name": r[1], "type": r[2], "not_null": bool(r[3]), "default": r[4], "pk": bool(r[5])}
                    for r in cur.fetchall()
                ]
                cur.execute(f'PRAGMA foreign_key_list("{escaped}")')
                fks = [{"from": r[3], "to_table": r[2], "to_col": r[4]} for r in cur.fetchall()]
                tables[name] = {"columns": cols, "foreign_keys": fks, "row_count": None}
            elif typ == "index":
                indexes.append({"name": name})
        return {"dialect": "sqlite", "path": str(db_path), "tables": tables, "indexes": indexes}
    finally:
        con.close()


# ---------- Postgres ----------
def _inspect_postgres(conn: str) -> dict[str, Any]:
    try:
        import psycopg  # type: ignore
    except ImportError:
        return {"error": "psycopg not installed", "hint": "pip install 'safe-migrations-mcp[postgres]'"}
    try:
        with psycopg.connect(conn) as c, c.cursor() as cur:
            cur.execute("""
                SELECT table_name, column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema='public' ORDER BY table_name, ordinal_position
            """)
            tables: dict[str, Any] = {}
            for tname, cname, dtype, nullable, default in cur.fetchall():
                tables.setdefault(tname, {"columns": [], "row_count": None})
                tables[tname]["columns"].append(
                    {"name": cname, "type": dtype, "not_null": nullable == "NO", "default": default}
                )
            cur.execute("SELECT relname, n_live_tup::bigint FROM pg_stat_user_tables")
            for tname, estimate in cur.fetchall():
                if tname in tables:
                    tables[tname]["row_count"] = estimate
            return {"dialect": "postgres", "tables": tables}
    except Exception as e:
        return {"error": f"postgres inspect failed: {e}"}


# ---------- MySQL ----------
def _inspect_mysql(conn: str) -> dict[str, Any]:
    try:
        import pymysql  # type: ignore
    except ImportError:
        return {"error": "pymysql not installed", "hint": "pip install 'safe-migrations-mcp[mysql]'"}
    u = urlparse(conn)
    try:
        c = pymysql.connect(
            host=u.hostname or "localhost", port=u.port or 3306,
            user=u.username or "root", password=u.password or "",
            database=(u.path or "/").lstrip("/"),
        )
        with c.cursor() as cur:
            cur.execute("SELECT DATABASE()")
            db = cur.fetchone()[0]
            cur.execute(
                "SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT "
                "FROM information_schema.columns WHERE TABLE_SCHEMA=%s ORDER BY TABLE_NAME, ORDINAL_POSITION",
                (db,),
            )
            tables: dict[str, Any] = {}
            for tname, cname, dtype, nullable, default in cur.fetchall():
                tables.setdefault(tname, {"columns": [], "row_count": None})
                tables[tname]["columns"].append(
                    {"name": cname, "type": dtype, "not_null": nullable == "NO", "default": default}
                )
            cur.execute(
                "SELECT TABLE_NAME, TABLE_ROWS FROM information_schema.tables WHERE TABLE_SCHEMA=%s",
                (db,),
            )
            for tname, estimate in cur.fetchall():
                if tname in tables:
                    tables[tname]["row_count"] = estimate
        c.close()
        return {"dialect": "mysql", "database": db, "tables": tables}
    except Exception as e:
        return {"error": f"mysql inspect failed: {e}"}


# ---------- Prisma ----------
_PRISMA_MODEL = re.compile(r"model\s+(\w+)\s*\{([^}]*)\}", re.DOTALL)
_PRISMA_FIELD = re.compile(r"^\s*(\w+)\s+([\w\[\]\?]+)(.*)$")


def _parse_prisma(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"error": f"Prisma file not found: {path}"}
    text = p.read_text(encoding="utf-8")
    tables: dict[str, Any] = {}
    for m in _PRISMA_MODEL.finditer(text):
        name, body = m.group(1), m.group(2)
        cols = []
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("@@"):
                continue
            fm = _PRISMA_FIELD.match(line)
            if fm:
                cols.append({
                    "name": fm.group(1),
                    "type": fm.group(2),
                    "not_null": "?" not in fm.group(2),
                    "attrs": fm.group(3).strip(),
                })
        tables[name] = {"columns": cols}
    return {"dialect": "prisma", "path": str(p), "tables": tables}


# ---------- Drizzle (best-effort) ----------
_DRIZZLE_TABLE = re.compile(r"(?:export\s+const\s+)?(\w+)\s*=\s*(?:pgTable|mysqlTable|sqliteTable)\(\s*['\"](\w+)['\"]", re.DOTALL)


def _parse_drizzle(path: str) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {"error": f"Drizzle file not found: {path}"}
    text = p.read_text(encoding="utf-8")
    detected_tables = {m.group(2): {"var": m.group(1)} for m in _DRIZZLE_TABLE.finditer(text)}
    return {
        "dialect": "drizzle",
        "path": str(p),
        "tables": {},
        "detected_tables": detected_tables,
        "unsupported": True,
        "note": "drizzle parsing is not complete enough for migration safety decisions",
    }


# ---------- Execution helpers ----------
def execute_sql(connection: str, sql: str, dry_run: bool = False) -> dict[str, Any]:
    k = _kind(connection)
    statements = split_sql(sql)
    if not statements:
        return {"ok": False, "error": "No SQL statements provided"}
    if len(statements) > _MAX_STATEMENTS:
        return {"ok": False, "error": f"Refusing to execute more than {_MAX_STATEMENTS} SQL statements in one proposal"}
    if k == "sqlite":
        path = _sqlite_path(connection)
        db_path = Path(path).expanduser()
        if not db_path.exists():
            return {"ok": False, "error": f"SQLite file not found: {path}"}
        con = sqlite3.connect(str(db_path))
        try:
            con.isolation_level = None  # manual txn
            cur = con.cursor()
            cur.execute("BEGIN")
            affected = 0
            for stmt in statements:
                cur.execute(stmt)
                if cur.rowcount and cur.rowcount > 0:
                    affected += cur.rowcount
            if dry_run:
                cur.execute("ROLLBACK")
                return {"ok": True, "dry_run": True, "affected_rows": affected, "statements_executed": len(statements)}
            cur.execute("COMMIT")
            return {"ok": True, "affected_rows": affected, "statements_executed": len(statements)}
        except Exception as e:
            try: cur.execute("ROLLBACK")
            except Exception: pass
            return {"ok": False, "error": str(e)}
        finally:
            con.close()
    if k == "postgres":
        try:
            import psycopg  # type: ignore
        except ImportError:
            return {"ok": False, "error": "psycopg not installed"}
        try:
            with psycopg.connect(connection, autocommit=False) as c, c.cursor() as cur:
                affected = 0
                for stmt in statements:
                    cur.execute(stmt)
                    affected += max(cur.rowcount or 0, 0)
                if dry_run:
                    c.rollback()
                    return {"ok": True, "dry_run": True, "affected_rows": affected, "statements_executed": len(statements)}
                c.commit()
                return {"ok": True, "affected_rows": affected, "statements_executed": len(statements)}
        except Exception as e:
            return {"ok": False, "error": str(e)}
    if k == "mysql":
        if _contains_ddl(sql):
            return {
                "ok": False,
                "unsupported": True,
                "reason": "mysql_ddl_unsupported",
                "error": "MySQL DDL apply is intentionally unsupported because many DDL statements auto-commit; use external migration tooling or a shadow database.",
            }
        try:
            import pymysql  # type: ignore
        except ImportError:
            return {"ok": False, "error": "pymysql not installed"}
        u = urlparse(connection)
        c = pymysql.connect(
            host=u.hostname or "localhost", port=u.port or 3306,
            user=u.username or "root", password=u.password or "",
            database=(u.path or "/").lstrip("/"), autocommit=False,
        )
        try:
            with c.cursor() as cur:
                total = 0
                for stmt in statements:
                    cur.execute(stmt)
                    total += max(cur.rowcount or 0, 0)
            if dry_run:
                c.rollback()
                return {"ok": True, "dry_run": True, "affected_rows": total, "statements_executed": len(statements)}
            c.commit()
            return {"ok": True, "affected_rows": total, "statements_executed": len(statements)}
        except Exception as e:
            c.rollback()
            return {"ok": False, "error": str(e)}
        finally:
            c.close()
    return {"ok": False, "error": f"execute_sql not supported for {k}"}


def backup_plan(connection: str) -> dict[str, Any]:
    k = _kind(connection)
    if k == "sqlite":
        db_path = Path(_sqlite_path(connection)).expanduser()
        return {
            "kind": "sqlite-online-backup",
            "available": db_path.exists(),
            "path": str(db_path),
            "note": "SQLite backups use the online backup API before apply.",
        }
    return {
        "kind": k,
        "available": False,
        "path": None,
        "note": "No built-in durable backup for this connection. Use pg_dump/mysqldump or external snapshots.",
    }


def backup(connection: str) -> dict[str, Any]:
    k = _kind(connection)
    if k == "sqlite":
        snapshot = _backup_sqlite_database(_sqlite_path(connection))
        return {
            "kind": "sqlite-online-backup",
            "available": snapshot is not None,
            "backup": snapshot,
        }
    plan = backup_plan(connection)
    return {**plan, "backup": None}


def _contains_ddl(sql: str) -> bool:
    return bool(re.search(r"\b(CREATE|ALTER|DROP|TRUNCATE|RENAME)\b", sql, flags=re.IGNORECASE))


def _path_cache_key(kind: str, path: Path) -> str:
    try:
        stat = path.resolve().stat()
        return f"{kind}:{path.resolve()}:{int(stat.st_mtime_ns)}:{stat.st_size}"
    except FileNotFoundError:
        return f"{kind}:{path.resolve()}:missing"


def _quote_sqlite_ident(name: str) -> str:
    return name.replace('"', '""')


def _backup_sqlite_database(path: str) -> str | None:
    from . import state

    src_path = Path(path).expanduser()
    if not src_path.exists():
        return None
    dst = state.state_dir() / "snapshots" / f"{src_path.name}.{int(time.time())}.sqlite.bak"
    src = sqlite3.connect(str(src_path), timeout=1.0)
    dest = sqlite3.connect(str(dst), timeout=1.0)
    try:
        src.execute("PRAGMA busy_timeout = 1000")
        dest.execute("PRAGMA busy_timeout = 1000")
        src.backup(dest)
    except sqlite3.Error:
        try:
            dst.unlink()
        except FileNotFoundError:
            pass
        return None
    finally:
        dest.close()
        src.close()
    dst.chmod(0o600)
    return str(dst)
