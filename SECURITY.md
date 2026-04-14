# Security Policy

Safe Migrations MCP is a security-adjacent tool — it sits between AI agents
and your database / config files, so vulnerabilities here can mean real data
loss for the people using it. Reports get taken seriously.

## Supported versions

Only the latest minor release on PyPI receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Please don't open a public GitHub issue for security problems.**

Use GitHub's private vulnerability reporting:
👉 https://github.com/possibly6/safe-migrations-mcp/security/advisories/new

Include:

- A short description of the issue
- Steps to reproduce — ideally a minimal proof-of-concept
- The version affected (`pip show safe-migrations-mcp`)
- Your assessment of severity, if you have one

Acknowledgement target: 7 days. Fix or mitigation target for high/critical
issues: 30 days. This is a one-person side project — please calibrate
expectations accordingly. I'd rather under-promise and ship than the
opposite.

## Scope

**In scope (please report):**

- Bypassing the `confirmation_token` flow to apply changes without a fresh simulation
- Token forgery / replay across proposals
- Path traversal or symlink attacks via the config tools
- SQL injection through the proposal pipeline (the server runs SQL it composes)
- Secret leakage in tool returns, audit logs, or proposal storage
- Local privilege escalation via the snapshot or audit directories
- Any way to make `apply_change` write something the user didn't see in `simulate_impact`

**Out of scope:**

- Vulnerabilities that require an attacker to already control the agent prompt
  (the agent is part of the trust boundary, not outside it)
- Issues in upstream dependencies — please report those upstream
- Social engineering of the human in the loop

## Hardening already in place

If you find a hole in any of these, that's exactly the kind of thing I want
to hear about:

- Confirmation tokens are bound to a SHA-256 fingerprint of the proposal and
  expire after 15 minutes; editing the proposal invalidates the token
- Config files written via atomic `mkstemp` + `os.replace`, with symlink
  rejection and mode preservation
- SQLite inspection uses read-only URI mode (won't silently create new files)
- Secret payloads stored separately at mode `0600`, redacted from public
  proposal metadata, and purged on successful apply
- MySQL DDL apply is intentionally blocked (no real transaction safety on
  MySQL DDL — refusing to pretend otherwise)
- Connection strings are redacted before being returned to the agent

## Hall of fame

If your report leads to a fix and you'd like credit, you'll be listed here.
