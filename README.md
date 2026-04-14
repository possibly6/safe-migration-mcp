# Safe Migrations MCP

**The safety layer the agent ecosystem needs.**

Stops Claude Code, Cursor, OpenClaw, and other AI coding agents from quietly breaking your database schema or config files.

Every proposed change is diffed, risk-flagged, and requires a fresh simulation-issued confirmation token before a single byte is written.

An MCP server that gives AI coding agents a safe, auditable, human-in-the-loop way to propose and execute DB schema changes **and** everyday config edits — the exact class of change that silently corrupts production when an agent gets overconfident.

---

## Why this exists

Agents are great at *proposing* changes and terrible at *understanding the
blast radius* of those changes. A one-word YAML typo, a helpful `DROP COLUMN`,
a missing `WHERE` in an `UPDATE` — any of these can take a project down while
the agent cheerfully reports success.

Safe Migrations MCP puts a mandatory checkpoint between the agent and your
disk:

1. **Propose** — agent sends an intent (natural language or raw SQL, or a
   new config file); server returns a `proposal_id` and full rollback plan.
2. **Simulate** — dry-run inside a rolled-back transaction; count affected
   rows; surface every DROP, TRUNCATE, NOT-NULL-without-default, secret-key
   removal, etc.
3. **Apply** — only runs with the one-time `confirmation_token` returned by
   `simulate_impact`. Snapshots the
   file or DB first. Logs everything to an append-only audit trail.

Local-first. Zero cloud dependency. ~2k LOC of Python, hardened against the usual footguns (symlink writes, silent SQLite creation, MySQL DDL auto-commit, token replay, secret leakage in diffs).

Born from watching an OpenClaw agent break its own config file trying to make a "small" change. The fix is universal: any agent that can edit anything should have to slow down, show its work, and ask first.

---

## Install & run

```bash
pip install git+https://github.com/possibly6/safe-migrations-mcp
safe-migrations-mcp                      # speaks MCP over stdio
```

Or from a local clone:

```bash
git clone https://github.com/possibly6/safe-migrations-mcp
cd safe-migrations-mcp
pip install -e '.[all]'
safe-migrations-mcp
```

Optional extras (Postgres / MySQL drivers):

- `pip install 'git+https://github.com/possibly6/safe-migrations-mcp#egg=safe-migrations-mcp[postgres]'` — adds `psycopg`
- `pip install 'git+https://github.com/possibly6/safe-migrations-mcp#egg=safe-migrations-mcp[mysql]'`    — adds `PyMySQL`
- `pip install 'git+https://github.com/possibly6/safe-migrations-mcp#egg=safe-migrations-mcp[all]'`      — both

SQLite, YAML, JSON, `.env`, and Prisma/Drizzle schema-file parsing work with
zero extra deps.

---

## Wire it into your agent

### Claude Code / Claude Desktop

`~/.claude/claude_desktop_config.json` (or `~/.config/Claude/claude_desktop_config.json` on Linux):

```json
{
  "mcpServers": {
    "safe-migrations": {
      "command": "safe-migrations-mcp"
    }
  }
}
```

### Cursor

`~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "safe-migrations": { "command": "safe-migrations-mcp" }
  }
}
```

### OpenClaw / any MCP-capable agent

Point the agent at the `safe-migrations-mcp` binary on stdio. The tool names
match the list below.

---

## The 8 tools

| Tool | Purpose |
|---|---|
| `inspect_schema(connection)` | Current DB/ORM schema. Postgres, MySQL, SQLite, plus `schema.prisma` and Drizzle TS files. Cached 60s. |
| `inspect_config(path)` | Parse YAML / JSON / `.env` / Prisma / TOML; return keys and shape. |
| `propose_migration_or_edit(kind, …)` | Create a proposal from natural language, raw SQL, or a new config file. Returns `proposal_id` plus redacted previews and hashes. Nothing is written. |
| `simulate_impact(proposal_id)` | Dry-run the proposal. DB: rolled-back transaction + affected-row count + SQL/rollback previews. Config: unified diff + key delta. Always returns risk flags. |
| `generate_rollback(proposal_id \| sql)` | Exact undo SQL (or the config-snapshot restore path). |
| `apply_change(proposal_id, confirmation)` | **Requires the fresh `confirmation_token` from `simulate_impact`**. Snapshots first, then executes in a transaction. |
| `get_change_history(limit)` | Append-only audit log of every applied change. |
| `cleanup_state(max_age_days)` | Prune old proposal metadata, secret payloads, and snapshots from local state. |

---

## Example agent conversation (the confirmation flow)

> **You**: "Add a `last_login` timestamp column to `users` in `./demo.db`."

> **Agent** (silently): `propose_migration_or_edit(kind="db", connection="sqlite:///./demo.db", request="add column last_login of type TEXT to users")`
>
> → `proposal_id = p_9a1b2c3d4e`, `sql_preview = ALTER TABLE "users" ADD COLUMN "last_login" TEXT;`, `rollback_preview = ALTER TABLE "users" DROP COLUMN "last_login";`

> **Agent** (silently): `simulate_impact("p_9a1b2c3d4e")`
>
> → `risk_level = "low"`, `dry_run.ok = true`, `affected_rows = 0`

> **Agent** (to you):
>
> > I'd like to run: `ALTER TABLE "users" ADD COLUMN "last_login" TEXT;`
> > Risk: **low**. Rollback available. Confirm?

> **You**: "yes, confirm"

> **Agent** (silently): copies the `confirmation_token` from `simulate_impact(...)`
> and calls `apply_change("p_9a1b2c3d4e", "<that token>")` → done, audit logged.

And the dangerous case:

> **You**: "drop the orders table."

> **Agent** (silently): `propose_migration_or_edit(kind="db", ..., sql="DROP TABLE orders;")`
> → `simulate_impact(...)` returns `risk_level: "critical"`, flag: *"Drops an entire table (all data lost)"*.

> **Agent** (to you):
>
> > 🛑 This is a **critical** destructive change on 3 rows. Rollback can recreate the table
> > but **row data cannot be auto-restored** without a backup. Are you sure?
> > Reply with the exact `confirmation_token` from the simulation step to proceed.

The agent physically cannot execute until that token is passed through — the
server enforces it, not the model.

---

## Example prompts you can paste

**Claude / Cursor / OpenClaw:**

```
Use the safe-migrations MCP. Inspect sqlite:///./examples/demo.db.
Then propose adding a `phone` TEXT column to users (nullable).
Show me the proposal + simulated risk. Wait for my approval before applying with the confirmation token from simulate_impact.
```

```
Use safe-migrations to edit ./examples/config.yaml: set app.log_level to "debug".
Show the diff and risk first. Only apply after I confirm.
```

```
Use safe-migrations to audit recent changes — call get_change_history and
summarize the last 10 entries.
```

---

## Try the demo locally

```bash
git clone https://github.com/possibly6/safe-migrations-mcp
cd safe-migrations-mcp
pip install -e .
python examples/seed_demo.py            # creates examples/demo.db
safe-migrations-mcp                     # start the server
```

Then, from your MCP-connected agent:

- `inspect_schema("sqlite:///./examples/demo.db")`
- `inspect_config("./examples/config.yaml")`
- `propose_migration_or_edit(kind="db", connection="sqlite:///./examples/demo.db", request="create index on orders(status)")`
- `simulate_impact(...)` → `apply_change(..., "<confirmation_token>")`

---

## What gets flagged

**SQL risk rules (severity):**
- `DROP TABLE` / `DROP DATABASE` / `DROP SCHEMA` — **critical**
- `DROP COLUMN`, `TRUNCATE`, `DELETE`/`UPDATE` without `WHERE` — **high**
- `ALTER COLUMN … TYPE`, `RENAME TO`, `ADD COLUMN NOT NULL` without `DEFAULT`, `GRANT`/`REVOKE` — **medium**

**Config risk rules:**
- Removal of keys matching `database|db|auth|secret|token|production|prod|migration` — **high**
- Adding or changing values on keys matching `password|secret|api_key|token|private_key|database_url|dsn|credentials` — **medium**
- Any removed key — at least **medium**

Anything ≥ medium sets `confirmation_required: true`.
High-risk config changes are blocked from direct apply so the agent has to reduce scope or hand the edit back for manual review.

---

## State & audit

All local, all visible:

```
~/.safe-migrations-mcp/
├── proposals/    # redacted proposal metadata as JSON
├── secrets/      # private proposal payloads (0600), pruned with cleanup_state
├── snapshots/    # pre-change backups
└── audit.jsonl   # append-only log of applied changes (redacted)
```

Override with `SAFE_MIGRATIONS_HOME=/path`.

---

## When to use this

✅ **Use Safe Migrations MCP when:**
- You let an AI agent touch your database or config files
- You want every schema change diffed and confirmed before it runs
- You want an audit trail of every change an agent has ever made
- You want rollback SQL generated automatically
- You're tired of agents silently dropping columns or rewriting `.env` files

❌ **Use a real migration framework (Alembic / Prisma Migrate / Flyway) when:**
- You need versioned, repeatable migrations checked into source control
- You're running zero-downtime migrations on a production Postgres
- You need MySQL DDL apply support (this server intentionally blocks it — see FAQ)
- You want online schema changes / backfills / dual-writes

This is a **gatekeeper**, not a migration framework. They're complementary — author your migrations with Alembic, let agents propose runtime tweaks through this.

**In scope:** SQLite, Postgres, MySQL inspection / DML; YAML, JSON, `.env`, Prisma, Drizzle (best-effort). Natural-language intents for common DDL (add/drop/rename column, create index, drop table). Raw SQL pass-through with automatic best-effort rollback.

**Out of scope (on purpose):** MySQL DDL apply, full SQL dialect coverage, online schema migrations, arbitrary DSL translation. Safety and clarity beat breadth here — if a proposal is outside what we can analyze, we say so instead of guessing.

---

## FAQ

**Q: How is this different from Alembic, Prisma Migrate, or Flyway?**
A: Those are migration *frameworks* — they track, version, and apply schema changes you author by hand. This is a *gatekeeper* — it sits between an AI agent and your DB/configs and forces every change through diff → simulate → confirm → apply. Use both.

**Q: Can the agent bypass the confirmation token?**
A: Not from inside this server. The token is generated server-side, bound to a SHA-256 fingerprint of the proposal, and expires in 15 minutes. Editing the proposal invalidates the token. The agent must call `simulate_impact` to get a fresh one — and the client UI (Claude Code's prompt, Cursor's confirm dialog) is what makes a human actually read the proposal before that token gets passed back.

**Q: Does this work in CI?**
A: It's the wrong tool for CI. The whole point is a human checkpoint. In CI, use your normal migration framework with version-controlled SQL. Reach for this server when an *agent* (Claude Code, Cursor, OpenClaw) is the one proposing the edit.

**Q: What happens if the apply fails halfway through?**
A: SQLite changes run inside a transaction and roll back on error. Postgres applies via `psycopg` with explicit commit/rollback. Failed applies are marked `apply_failed`, *not* `applied`, and audited as a separate event so you can find them later.

**Q: Why is MySQL DDL apply intentionally blocked?**
A: MySQL auto-commits DDL — there's no real "dry-run inside a transaction" or rollback. This server refuses to pretend it has a safety net it doesn't have. MySQL DML (INSERT/UPDATE/DELETE) and inspection still work fine.

**Q: Does it know about my Postgres triggers, views, or functions?**
A: Not in v0.1 — inspection covers tables and columns. Triggers/views/functions are out of scope for now.

**Q: My agent has a raw `write_file` tool too. Can't it just bypass the MCP?**
A: Yes — the safety is opt-in at the agent's tool level. If you wire `safe-migrations` in *and* leave a raw filesystem write tool enabled for the same paths, the agent can route around the gate. The intended pattern is: route DB and config edits through this server, and keep raw filesystem writes scoped to other paths.

---

## Development

```bash
pip install -e '.[all]'
pip install pytest
pytest -q
```

---

## License

MIT.
