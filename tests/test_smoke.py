"""Smoke tests — no MCP transport, call the tool functions directly."""
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Isolate state dir per run
os.environ["SAFE_MIGRATIONS_HOME"] = tempfile.mkdtemp(prefix="smoke-")

from safe_migrations_mcp import db, config as cfg, migration, safety, state, server as servermod  # noqa: E402
from safe_migrations_mcp.server import (  # noqa: E402
    inspect_schema, inspect_config, propose_migration_or_edit,
    simulate_impact, generate_rollback, apply_change, get_change_history, cleanup_state,
)


def _seed_db(tmp: Path) -> str:
    db_path = tmp / "t.db"
    con = sqlite3.connect(db_path)
    con.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);"
        "INSERT INTO users (email) VALUES ('a@x'),('b@x');"
    )
    con.commit(); con.close()
    return str(db_path)


def test_inspect_and_propose_add_column(tmp_path):
    dbp = _seed_db(tmp_path)
    conn = f"sqlite:///{dbp}"
    schema = inspect_schema(conn)
    assert "users" in schema["tables"]

    r = propose_migration_or_edit(
        kind="db", connection=conn,
        request="add column name of type TEXT to users",
    )
    pid = r["proposal_id"]
    assert "ALTER TABLE" in r["sql_preview"]
    assert "DROP COLUMN" in r["rollback_preview"]
    assert "connection_preview" in r
    assert "sql" not in r

    sim = simulate_impact(pid)
    assert sim["dry_run"]["ok"] is True
    assert sim["confirmation_token"]
    assert "sql" not in sim
    assert "rollback" not in sim

    bad = apply_change(pid, "no")
    assert bad["ok"] is False

    sim = simulate_impact(pid)
    ok = apply_change(pid, sim["confirmation_token"])
    assert ok["ok"] is True

    schema2 = inspect_schema(conn, refresh=True)
    col_names = [c["name"] for c in schema2["tables"]["users"]["columns"]]
    assert "name" in col_names


def test_dangerous_sql_flagged(tmp_path):
    dbp = _seed_db(tmp_path)
    conn = f"sqlite:///{dbp}"
    r = propose_migration_or_edit(kind="db", connection=conn, sql="DROP TABLE users;")
    sim = simulate_impact(r["proposal_id"])
    assert sim["risk"]["risk_level"] == "critical"
    assert sim["confirmation_required"] is True


def test_config_edit_flow(tmp_path):
    p = tmp_path / "app.yaml"
    p.write_text("app:\n  port: 3000\n")
    new = "app:\n  port: 3001\n"
    r = propose_migration_or_edit(kind="config", path=str(p), new_content=new)
    pid = r["proposal_id"]
    sim = simulate_impact(pid)
    assert "unified_diff" in sim["diff"]

    ok = apply_change(pid, sim["confirmation_token"])
    assert ok["ok"] is True
    assert "3001" in p.read_text()
    # backup made
    assert ok["backup"] and Path(ok["backup"]).exists()


def test_env_removes_flagged_high(tmp_path):
    p = tmp_path / ".env"
    p.write_text("DATABASE_URL=sqlite:///x.db\nAPI_KEY=abc\n")
    new = "API_KEY=abc\n"
    r = propose_migration_or_edit(kind="config", path=str(p), new_content=new)
    sim = simulate_impact(r["proposal_id"])
    assert sim["risk"]["risk_level"] in ("high", "critical")
    assert sim["appliable"] is False
    assert sim["confirmation_token"] is None


def test_history_records_applied(tmp_path):
    dbp = _seed_db(tmp_path)
    conn = f"sqlite:///{dbp}"
    r = propose_migration_or_edit(
        kind="db", connection=conn, sql='ALTER TABLE "users" ADD COLUMN "x" TEXT;'
    )
    sim = simulate_impact(r["proposal_id"])
    apply_change(r["proposal_id"], sim["confirmation_token"])
    hist = get_change_history()
    assert any(e["event"] == "db.apply" for e in hist["entries"])


def test_apply_requires_fresh_simulation_token(tmp_path):
    dbp = _seed_db(tmp_path)
    conn = f"sqlite:///{dbp}"
    proposal = propose_migration_or_edit(
        kind="db", connection=conn, sql='ALTER TABLE "users" ADD COLUMN "nickname" TEXT;'
    )
    blocked = apply_change(proposal["proposal_id"], "CONFIRM anything")
    assert blocked["ok"] is False
    assert "simulated" in blocked["error"]


def test_failed_apply_not_marked_applied(tmp_path):
    p = tmp_path / "settings.json"
    p.write_text('{"ok": true}\n')
    proposal = propose_migration_or_edit(
        kind="config", path=str(p), new_content='{"ok": false}\n'
    )
    sim = simulate_impact(proposal["proposal_id"])
    p.unlink()
    p.mkdir()
    result = apply_change(proposal["proposal_id"], sim["confirmation_token"])
    assert result["ok"] is False

    stored = state.load_proposal(proposal["proposal_id"])
    assert stored["status"] in {"apply_failed", "apply_blocked"}
    assert stored.get("applied") is not True


def test_missing_sqlite_file_is_rejected():
    missing = "/tmp/definitely-not-here-safe-migrations.db"
    result = db.execute_sql(missing, 'CREATE TABLE demo (id INTEGER);', dry_run=True)
    assert result["ok"] is False
    assert "not found" in result["error"]


def test_env_export_is_parsed_cleanly(tmp_path):
    p = tmp_path / ".env"
    p.write_text('export DATABASE_URL="sqlite:///x.db"\nAPI_KEY=abc\n')
    inspected = cfg.inspect_config_file(str(p))
    assert inspected["keys"] == ["DATABASE_URL", "API_KEY"]


def test_invalid_json_config_is_blocked(tmp_path):
    p = tmp_path / "settings.json"
    p.write_text('{"ok": true}\n')
    proposal = propose_migration_or_edit(kind="config", path=str(p), new_content='{"bad": }\n')
    sim = simulate_impact(proposal["proposal_id"])
    assert sim["appliable"] is False
    assert sim["confirmation_token"] is None


def test_proposal_state_redacts_sensitive_fields(tmp_path):
    p = tmp_path / ".env"
    p.write_text("TOKEN=old\n")
    proposal = propose_migration_or_edit(
        kind="config",
        path=str(p),
        new_content="DATABASE_URL=postgresql://user:secret@db.internal/app\nTOKEN=new\n",
    )
    stored_path = state.state_dir() / "proposals" / f"{proposal['proposal_id']}.json"
    raw = stored_path.read_text()
    assert "postgresql://user:secret@db.internal/app" not in raw
    assert '"new_content"' in raw
    assert "<redacted>" in raw


def test_confirmation_token_not_persisted_in_plaintext(tmp_path):
    dbp = _seed_db(tmp_path)
    conn = f"sqlite:///{dbp}"
    proposal = propose_migration_or_edit(
        kind="db", connection=conn, sql='ALTER TABLE "users" ADD COLUMN "nickname" TEXT;'
    )
    sim = simulate_impact(proposal["proposal_id"])
    stored_path = state.state_dir() / "proposals" / f"{proposal['proposal_id']}.json"
    raw = stored_path.read_text()
    assert sim["confirmation_token"] not in raw
    assert "token_hash" in raw


def test_audit_redacts_connection_credentials(tmp_path):
    dbp = _seed_db(tmp_path)
    conn = "postgresql://user:secret@example.com/app"
    state.audit({"event": "db.apply", "connection": conn, "sql": "SELECT 1;"})
    raw = state.audit_log_path().read_text()
    assert "secret@" not in raw
    assert "<redacted>" in raw


def test_db_proposal_response_redacts_connection_preview():
    rendered = servermod._redact_connection("postgresql://user:secret@example.com/app")
    assert "secret@" not in rendered
    assert "<redacted>" in rendered


def test_multistatement_update_without_where_is_still_flagged():
    risk = safety.analyze_sql("UPDATE users SET email='x'; SELECT 1 WHERE 1=1;")
    assert risk["risk_level"] in {"high", "critical"}


def test_preview_redacts_url_credentials():
    preview = cfg.inspect_config_file.__globals__["_safe_preview"]("APP_URL=https://user:secret@internal.example\n")
    assert "secret@" not in preview
    assert "<redacted>" in preview


def test_dangling_symlink_path_is_rejected(tmp_path):
    broken_dir = tmp_path / "broken"
    broken_dir.symlink_to(tmp_path / "missing-dir", target_is_directory=True)
    issue = cfg.validate_config_target(str(broken_dir / "app.env"), for_write=True)
    assert issue is not None
    assert "symlinked config path" in issue


def test_bad_confirmation_clears_pending_token(tmp_path):
    dbp = _seed_db(tmp_path)
    conn = f"sqlite:///{dbp}"
    proposal = propose_migration_or_edit(
        kind="db", connection=conn, sql='ALTER TABLE "users" ADD COLUMN "nickname" TEXT;'
    )
    simulate_impact(proposal["proposal_id"])
    blocked = apply_change(proposal["proposal_id"], "CONFIRM nope")
    assert blocked["ok"] is False
    stored = state.load_proposal(proposal["proposal_id"])
    assert stored["pending_confirmation"] is None


def test_mysql_ddl_is_explicitly_unsupported():
    conn = "mysql://root:pw@localhost/app"
    result = db.execute_sql(conn, "ALTER TABLE users ADD COLUMN nickname TEXT;", dry_run=True)
    assert result["ok"] is False
    assert result["unsupported"] is True
    assert result["reason"] == "mysql_ddl_unsupported"


def test_config_apply_purges_secret_payload(tmp_path):
    p = tmp_path / "app.yaml"
    p.write_text("app:\n  port: 3000\n")
    proposal = propose_migration_or_edit(kind="config", path=str(p), new_content="app:\n  port: 3001\n")
    secret_path = state.state_dir() / "secrets" / f"{proposal['proposal_id']}.json"
    sim = simulate_impact(proposal["proposal_id"])
    result = apply_change(proposal["proposal_id"], sim["confirmation_token"])
    assert result["ok"] is True
    assert not secret_path.exists()


def test_cleanup_state_prunes_old_files():
    proposal_path = state.state_dir() / "proposals" / "old.json"
    secret_path = state.state_dir() / "secrets" / "old.json"
    snapshot_path = state.state_dir() / "snapshots" / "old.bak"
    for path in (proposal_path, secret_path, snapshot_path):
        path.write_text("{}", encoding="utf-8")
        old_ts = 1
        os.utime(path, (old_ts, old_ts))
    result = cleanup_state(max_age_days=1)
    assert result["ok"] is True
    assert result["removed"]["proposals"] >= 1
    assert result["removed"]["secrets"] >= 1
    assert result["removed"]["snapshots"] >= 1
    assert not proposal_path.exists()
    assert not secret_path.exists()
    assert not snapshot_path.exists()
