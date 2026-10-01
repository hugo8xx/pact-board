# PACT Board

An MCP server where Claude (web, Desktop, Cowork, Claude Code), Gemini and a headless Runner
share work on one board. Every call carries a **mandate**: a chain of authority that traces back
to a human, checked on every call, narrowing at each hand-off, revocable at any link.

## How it fits together

| Piece | What it is |
| --- | --- |
| `pact-board` (this repo) | the MCP server: 7 tools, mandates, the append-only hash-chained log |
| An OAuth 2.1 authorization server | signs people in for the hosted Claude apps. Bring any that issues JWT access tokens with a JWKS and supports CIMD or DCR (Keycloak, WorkOS, Auth0, …) |
| Agent tokens | `pact_…` bearer tokens for Claude Code, Gemini CLI, hooks and the Runner — no OAuth needed |
| `admin/` | the Admin UI (Next.js, for Vercel). It calls the board's Admin API at `/admin/api` |

Each agent has its own URL: `https://<board>/mcp/a/<agent-id>`. With OAuth, the signed-in person
must be the agent's owner; the board matches them to a registered human by verified email once,
then by the token's `sub`.

## Tools

`pact_whoami` · `pact_post` · `pact_list` · `pact_claim` · `pact_report` · `pact_defer` · `pact_revoke`.
A mandate delegated with `pact_post` lives only as long as its task: once the task is completed,
failed, canceled or rejected, that mandate and everything under it is revoked, and open subtasks
posted under it are canceled. `pact-admin migrate` sweeps any left over from before this rule.
Refusals come back as `is_error` results whose text is JSON: `{"error": "<code>", "message": …, "mandate_id": …}`.

## Run locally

```bash
cp .env.example .env            # set DATABASE_URL and a long random PACT_SIGNING_KEY
createdb pact_dev
uv sync
uv run pact-admin migrate
uv run pact-admin human-add alice "Alice" owner --email alice@example.com   # the first person bootstraps as owner
uv run pact-admin project-add web "Web" --by alice
uv run pact-admin agent-register code-web --by alice --client code --projects web
uv run pact-board                                                              # http://127.0.0.1:8787
```

`agent-register` prints the agent's root mandate and a bearer token (shown once). For Claude Code,
put the agent's URL and token in the repo's `.mcp.json`:

```json
{ "mcpServers": { "pact": {
    "type": "http",
    "url": "http://127.0.0.1:8787/mcp/a/code-web",
    "headers": { "Authorization": "Bearer ${PACT_TOKEN}" } } } }
```

`uv run pact-admin --help` lists the human-side commands (approve, resume, pause, freeze, halt,
revoke, erase a payload, verify the log).

## Claude Code hooks

Two optional hooks connect a Claude Code session to the board. Neither claims work.

| Hook | What it does |
| --- | --- |
| `PostToolUse` | logs each shell command and file edit as an Entry on the one task the agent is working on (secrets redacted, output not kept). These entries are heartbeats, so a long task is not released. With no task in hand, nothing is logged. |
| `Stop` | after each reply, tells the person (not the model) when open tasks arrived since that session last looked. |

Set up, per repo:

1. Put the agent's URL and token outside the repo, readable only by you:
   `~/.config/pact/<agent-id>.env` containing `PACT_URL=https://<board>` and `PACT_TOKEN=pact_…` (`chmod 600`).
2. Copy the `hooks` block of [`hooks/settings.local.example.json`](hooks/settings.local.example.json) into the repo's
   `.claude/settings.local.json` (not `settings.json`, which is committed), with the path to `hooks/pact-hook.sh`
   and the agent id.

The script needs only `sh` and `curl`. If the config is missing or the board is down it prints nothing and exits 0.
The board serves the hooks at `POST /hooks/a/<agent-id>/{post-tool-use,stop}` and accepts agent tokens only.

## Admin API

`/admin/api/*` is for people, not agents: it takes an OAuth access token whose audience is
`<PACT_PUBLIC_URL>/admin`, signed in with a second factor (`amr` contains `mfa`). Agent tokens and
tokens minted for agent URLs are refused. Roles: owners do everything (kill switch, production
flag, freezing, banning); approvers approve tasks, register agents and issue or revoke mandates;
viewers read. See [`admin/`](admin/README.md) for the UI.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | yes | Postgres connection string |
| `PACT_SIGNING_KEY` | yes | ≥ 32 random characters; signs mandates. Changing it invalidates every mandate |
| `PACT_PUBLIC_URL` | yes in production | this server's public URL, e.g. `https://board.example.com` |
| `PACT_AUTH_ISSUER` | for the hosted Claude apps | your authorization server's issuer URL; unset = agent tokens only |
| `PACT_ADMIN_REQUIRE_MFA` | no | default `1`; set `0` only if your issuer never reports `amr` |
| `PORT`, `HOST` | no | default `8787`, `127.0.0.1` (`0.0.0.0` in the container) |

## Deploy on Railway

1. Create a project, add a **PostgreSQL** service.
2. Add a service from this repo. Railway builds the `Dockerfile`; `railway.json` sets the health check.
3. Set the variables above. `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`. Generate a public domain
   and put it in `PACT_PUBLIC_URL`.
4. Deploy. Migrations run on start. Then, from your machine with the same `DATABASE_URL`
   (Railway shows a public proxy URL), run the `pact-admin` commands above.
5. In Claude: *Settings → Connectors → Add custom connector* → `https://<domain>/mcp/a/<agent-id>`.

## Checks

```bash
createdb pact_test               # once; .env.test points DATABASE_URL at it
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```

The test suite drops and recreates the `public` schema of the test database on every run.

## Layout

| Path | What |
| --- | --- |
| `src/pact/board.py` | the 7 tools as plain async methods |
| `src/pact/mandates.py` | issuing, whole-chain verification, aggregate limits, revocation |
| `src/pact/entries.py` | append-only log, one hash chain per project, PDPA payload erasure |
| `src/pact/admin.py` | human-only operations (the Admin UI backend) |
| `src/pact/oauth.py` | the board as an OAuth protected resource (RFC 9728, JWKS verification) |
| `src/pact/server.py` | MCP tools, `/mcp/a/<agent>` routing, agent-token and OAuth auth |
| `src/pact/hooks.py` | the Claude Code hook endpoints |
| `hooks/` | the hook script and a settings example |
| `src/pact/migrations/` | SQL schema |
| `tests/` | one test per done-criterion |

## License

[Apache-2.0](LICENSE)
