# pact-board

Read by Claude Code sessions in this repository, including PACT Runner sessions. This repo is
public: keep it free of any one person's or company's names, hosts and secrets.

## Layout

- `src/pact/`: the board, an MCP server (MCP SDK v2, psycopg 3), plus the Admin API at `/admin/api`
  and the `pact-admin` CLI. Schema changes are new numbered files in `src/pact/migrations/`; never
  edit one that has shipped.
- `src/pact_runner/`: PACT Runner (headless `claude -p` per task), `pact-runner-guard` and `pact-connect`.
- `tests/`: pytest against a real Postgres (`pact_test` by default, or `DATABASE_URL`).

## Checks

Run all four after every edit, even a one-line one, and before opening a PR:

```
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```

A runner should use its own test database through `DATABASE_URL` so it never collides with another.

## Git

- Work on a branch and open a PR. Never push to `main`, never force-push a shared branch, never merge.
- Conventional Commits (`feat(runner): …`, `fix(board): …`); the body says why.
- Merging to `main` deploys, so a PR must be complete: code, tests, README when behaviour changes.
