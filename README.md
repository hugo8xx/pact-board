# PACT Board

An MCP server where Claude (web, Desktop, Cowork, Claude Code), Gemini and a headless Runner
share work on one board. Every call carries a **mandate**: a chain of authority that traces back
to a human, checked on every call, narrowing at each hand-off, revocable at any link.

## How it fits together

| Piece | What it is |
| --- | --- |
| `pact-board` (this repo) | the MCP server: 8 tools, project context, mandates, the append-only hash-chained log |
| An OAuth 2.1 authorization server | signs people in for the hosted Claude apps. Bring any that issues JWT access tokens with a JWKS and supports CIMD or DCR (Keycloak, WorkOS, Auth0, …) |
| Agent tokens | `pact_…` bearer tokens for Claude Code, Gemini CLI, hooks and the Runner — no OAuth needed |
| [`pact-admin`](https://github.com/hugo8xx/pact-admin) (separate repo) | the Admin UI (Next.js, on Vercel). It calls the board's Admin API at `/admin/api` |

Each agent has its own URL: `https://<board>/mcp/a/<agent-id>`. With OAuth, the signed-in person
must be the agent's owner; the board matches them to a registered human by verified email once,
then by the token's `sub`.

Client types: `chat` and `cowork` post and watch tasks but never claim them; `design` (Claude Design),
`code`, `gemini` and `runner` claim and report. Claude Design has no connector settings of its own: it
uses every claude.ai connector, so a `design` agent is a second claude.ai connector pointing at the
design agent's URL, and Chat sees it too.

## Tools

`pact_whoami` · `pact_post` · `pact_list` · `pact_claim` · `pact_report` · `pact_defer` · `pact_revoke` · `pact_note`.

**Project context.** `pact_note` holds a project's shared knowledge (decisions, conventions, links) so
every agent reads the same thing without anyone retelling it. Reading needs `task.read`; writing needs
`context.write@project:<p>`, which a fresh registration does not grant. A note a person pins in the Admin
UI is read-only for agents. Notes are redacted, versioned, erasable (PDPA), and served as reference data
with their author, never as instructions. They are also MCP resources:
`pact://projects/<p>/context` and `pact://projects/<p>/context/<key>`. `pact_whoami` lists their titles.

**Signatures and credentials.** The board signs every mandate with Ed25519 and publishes the public
keys at `/.well-known/pact-keys.json`, so a verifier elsewhere can check what the board issued. To
rotate, put a new `PACT_BOARD_KEYS` entry first and keep the old one until the mandates it signed have
expired. Mandates signed before Ed25519 (an HMAC under `PACT_SIGNING_KEY`) keep verifying. The ledger
stays the source of truth; `pact.credentials` is the interface that exports it as, or imports it from,
standard delegation credentials (Tenuo or Biscuit, by `PACT_EXPORT_FORMAT`). Agents that hold exported credentials
register an Ed25519 public key (`pact-admin agent-key-add`, code and runner agents only).

**Exported credentials (Tenuo).** With `PACT_EXPORT_FORMAT=tenuo`, `pact_claim` also hands an agent
that has a registered key a credential for the mandate it claimed with:
`"credential": {"format": "tenuo", "external_id": …, "warrant_stack": <base64>}`. A tool server
outside the board can then check each call offline, trusting only the board's public keys
(`examples/tenuo_verifier/`). The stack holds one warrant per ledger link, all held and signed by
the board, then a leaf held by the agent's key, which signs every call (proof of possession); the
board never sees an agent's private key. The leaf lives at most `PACT_EXPORT_TTL_HOURS` (default 24)
and is re-issued on each claim. `action@project:P` becomes Tenuo tool `action` with
`project` constrained to P; each limit becomes a per-call ceiling (every call must pass every
limit key); `task_id` is the one free argument; the TTL follows the link's expiry, at most 90 days.
When no credential can be issued (no key, or a wildcard scope such as `task.*`) the claim still
succeeds and says why in `credential_note`. Unset, claims are unchanged. The ledger stays the
source of truth: cumulative limits, DEFER and approvals are enforced only by the board.

Revoking a mandate on the board (`pact_revoke`, the Admin, closing or reassigning a task) puts every
credential id minted for it and for everything under it on a signed revocation list, one per format,
published at `GET /.well-known/pact-revocations/<format>` (version in `x-pact-revocations-version`;
an unknown format is a 404). For Tenuo that is `/.well-known/pact-revocations/tenuo`, a Tenuo SRL
(`application/octet-stream`). Verifiers must refetch it at least every 60 seconds and must fail
closed, refusing every call, when they cannot.

**Exported credentials (Biscuit).** `PACT_EXPORT_FORMAT=biscuit` swaps the format and nothing else:
the claim carries `"credential": {"format": "biscuit", "external_id": …, "biscuit": <base64url token>}`.
The token has one block per ledger link: the authority block for the root link, signed with the
board's active key (its Biscuit root key id is the first 4 bytes of SHA-256 of the public key, so a
verifier picks the right JWKS key after a rotation), then one attenuation block per later link. Each
block holds Datalog checks for its link's scope (`tool(a), project(p)`), per-call limits
(`arg(k, $v), $v <= max`, in millionths because Biscuit has integers only) and expiry; the last
block also carries `holder("<agent key>")` and refuses arguments nobody constrained. A verifier adds
`tool(…)`, `project(…)`, `arg(…)` and `time(…)` facts (`pact.credentials.biscuit.authorizer_for`).
Every block has a revocation id and a token's ids include its parents', so revoking any link fails
every token minted through it. Biscuit has no revocation list format, so the board publishes JSON
at `/.well-known/pact-revocations/biscuit` (`application/json`):
`{"payload": "<canonical JSON>", "signature": "ed25519:<kid>:<base64url>"}`, where the payload is
`{"format":"biscuit","issued_at":…,"revoked":[<hex ids>],"version":n}` (sorted keys, no spaces) and
the signature is over its UTF-8 bytes with the JWKS key named by `kid`
(`pact.credentials.biscuit.verify_revocation_list`). Importing Biscuit tokens is not supported yet.

| | Tenuo | Biscuit |
| --- | --- | --- |
| Proof of possession | yes: the agent signs every call with its key | **no**: a bearer token; whoever has it can use it until it expires or is revoked |
| Holder binding | leaf warrant held by the agent's key | `holder(…)` fact, informational only |
| Revocation list | Tenuo SRL, board-signed | board-signed JSON (above) |
| A later link widening | refused by Tenuo | not an error, but ineffective: only the authority block's `right` facts grant |
| Shape | one board-held warrant per link + the agent's leaf | one block per link |

Pick Tenuo where a leaked credential must be useless to someone else; Biscuit only where the
verifier authenticates its caller some other way.

**Imported credentials (Tenuo).** An organization that issues its own Tenuo warrants can give one
to a PACT agent, and the board turns it into a root mandate. First an owner registers the
organization's Ed25519 key as a **trusted root** standing for a registered person
(`pact-admin trusted-root-add <key> --human <id>`, or `POST /admin/api/trusted-roots`
`{public_key, human, label}`; list with `GET`, revoke with `DELETE /admin/api/trusted-roots/{key}`).
Then an approver imports the warrant stack for an agent (`pact-admin credential-import <agent>
<stack>`, or `POST /admin/api/agents/{id}/credentials` `{format: "tenuo", credential}`). Agents
can never import for themselves: there is no MCP tool for it. The board verifies the stack against
live trusted roots only (signatures, linkage, attenuation, expiry; anything else is
`chain_broken`), and requires the leaf's holder to be one of the agent's live registered keys and
every scope to fall within the agent's projects (`project_mismatch`). The new root mandate's issuer
is the trusted root's person, so its entries trace to a human; it expires with the warrant, and may
delegate twice on the board (0 when the leaf is terminal, never more than Tenuo's remaining depth).
Mapping is the export's in reverse: tool `T` with `project` `Exact(P)` or `OneOf([P, …])` becomes
`T@project:P`; each `Range.max_value(v)` becomes a limit (the tightest across tools); `task_id` may
be `Wildcard`. Anything else is refused with `invalid_request` rather than dropped, since dropping
a constraint would widen what the issuer granted: a tool without `project`, a wildcard tool name,
other constraint types (`Pattern`, `Range` with a minimum, …), other arguments, outside approvals.
Revoking the trusted root stops every mandate imported under it (`mandate_revoked`). A revoked key
can be added again (`trusted-root-add` with the same key reactivates it), but only from then on:
mandates imported before the revoke stay dead and must be imported anew. An agent's
`pact_revoke` of an imported root gets `not_issuer`, and people revoke it like any root mandate.

**Handoff.** `pact_report` with `completed`, `failed` or `canceled` must carry a handoff in `result`:
a markdown section headed `Handoff` (what was done; repo / branch / PR / commit; checks; what is left;
what needs a human; links), or an object with a `handoff` key. Without it the board refuses with
`handoff_required` and the task stays open. Heartbeats (`working`) and `input_required` need none.

**Budgets.** A mandate's `limits` are free-form numeric ceilings, and every amount spent counts
against each link above it, so a child never spends more than its parents hold. Runners use two
keys: `runs` and `turns`. `pact_claim` with `reserve={"runs": 1}` takes a run in the claim's own
transaction (no room left: `limit_exceeded`, and the task stays free). `pact_report` with
`usage={"turns": 12}` records what a run already spent, even past a ceiling, and then answers
`budget_exceeded` with the keys that ran out, so the agent stops. When the chain has limits, both
answer with `budget`: what is left of each limit, the tightest across the chain. An agent can hand part of its budget to a
sub-agent through `pact_post(delegate_to=…, child_limits=…)` without asking a person, as long as it
stays within its own.

**Agent preferences.** Each agent has a JSON object of preferences (how it should work: language,
report style, …), set by people with `pact-admin agent-prefs` or the Admin API
(`PUT /admin/api/agents/<id>/preferences`) and handed to the agent in `pact_whoami`. They ride along in
every session, so they are capped at 4000 characters.

**Daily brief.** A task with action `report.brief` is a report for people. When it completes, its whole
result goes out as one `brief` notification. The result is redacted, cut to 2800 characters and its
Handoff section dropped, so it isn't just a "task closed" line. A runner with a `report.brief` schedule
and a chief-of-staff role (`examples/runner/secretary-role.md` in pact-runner) sends the CEO a morning brief this way.
When the result carries a `report` (`{"greeting", "sections": [{"title", "items": [{"text", "task_id"}]}]}`,
which a Runner session returns in its structured output), the brief becomes one Slack card. Each item
about a task gets an "open task" button.

**Slack cards.** Notifications are Block Kit cards: an icon and headline, the task's title and detail,
the project and agent, and a button to the task in the Admin UI (`PACT_ADMIN_UI_URL`). An incoming
webhook can show link buttons but cannot receive clicks, so approving still happens in the Admin UI.

**Notifications.** The board tells people when it needs them: a task waiting for approval, a task
deferred or asking a question (`input_required`), a top-level task closing, and a task delegated to a
`chat`, `cowork` or `design` agent, which works only while a person has it open. It also warns when
an active agent's root mandate (the newest one a person issued) or its newest token is about to expire
(`PACT_EXPIRY_WARN_HOURS`, default 48) and again once it has expired, since an agent without them simply
stops. Each warning is sent once, and something that expired more than a day ago is never announced.
The sender process checks every 10 minutes. Each is written to a
`notifications` outbox in the same transaction as the event; a sender posts pending rows to Slack
(`PACT_SLACK_WEBHOOK_URL`), retrying with backoff, so a Slack outage never fails board work. Messages
carry a redacted, shortened title and first line of detail plus a link to the task, never its body.

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

Optional hooks connect a Claude Code session to the board. Only `UserPromptSubmit` ever claims work.

| Hook | What it does |
| --- | --- |
| `SessionStart` | when a session opens, shows the person the open tasks. Never claims. |
| `UserPromptSubmit` | auto-claim: when the person types, claims the oldest task delegated to this agent, only if every condition below holds, and hands it to Claude framed as another agent's request (the person's messages take precedence). Otherwise it says why nothing was claimed. |
| `PostToolUse` | logs each shell command and file edit as an Entry on the one task the agent is working on (secrets redacted, output not kept). These entries are heartbeats, so a long task is not released. With no task in hand, nothing is logged. |
| `Stop` | after each reply, tells the person (not the model) when open tasks arrived since that session last looked. |

Auto-claim takes a task only when all of these hold; missing any one, it claims nothing and tells the person why:

1. the repo turned it on: `PACT_AUTO_CLAIM=1` in the agent's env file (off by default);
2. the task's `delegate_to` is this agent, and its sender is listed in `PACT_AUTO_CLAIM_FROM` (comma-separated agent ids);
3. the session's permission mode is `default`, so Claude still asks before acting;
4. the working tree is clean (no uncommitted or staged changes);
5. the agent holds no other task (the claim is `exclusive`, so two sessions of one agent cannot each take one);
6. the project is not marked production, and not frozen.

Set up, per repo:

1. Put the agent's URL and token outside the repo, readable only by you:
   `~/.config/pact/<agent-id>.env` containing `PACT_URL=https://<board>` and `PACT_TOKEN=pact_…` (`chmod 600`).
2. Copy the `hooks` block of [`hooks/settings.local.example.json`](hooks/settings.local.example.json) into the repo's
   `.claude/settings.local.json` (not `settings.json`, which is committed), with the path to `hooks/pact-hook.sh`
   and the agent id.

The script needs only `sh` and `curl`. If the config is missing or the board is down it prints nothing and exits 0.
The board serves the hooks at `POST /hooks/a/<agent-id>/{session-start,user-prompt-submit,post-tool-use,stop}` and accepts
agent tokens only. The script reports what the board cannot see in `X-Pact-Auto-Claim`, `X-Pact-Auto-Claim-From` and
`X-Pact-Git-Clean` headers.

## Hiring agents

People hire agents from **roles** instead of registering them by hand. A role is a job description
kept in the Admin UI (`agent_roles`; eight ship with the board: chat, code, gemini, runner, worker,
secretary, design, cowork). It says what the agent can do, the project-relative actions its mandate grants
(e.g. `task.work`), its budget (`limits`), how far it may delegate, how long its mandate and token
last, and, for a Runner, the `PACT_RUNNER_*` settings and instructions its machine runs with.

- `POST /admin/api/agents/hire {role, project, id?, limits?, delegations?, days?, owner?, replaces?}`
  - registers `<role>-<project>` (or `id`) with the role's scope, budget and term in one step, and answers how to connect it.
  - An agent that signs in through a Claude app (chat, cowork, design) gets its connector URL.
  - One that uses a token (code, runner) gets a **one-time setup code**, valid for 15 minutes, never the token itself.
  - `owner` hires it for another registered person. An OAuth agent answers only to its owner.
  - `replaces` bans the old agent and makes the board tell anyone still calling it which agent took over.
- `pact-connect <board-url> <setup-code>` (installed with [pact-runner](https://github.com/hugo8xx/pact-runner)) runs on the machine the agent will use. It posts the code to `POST /connect` and gets the token back once. It then writes the token straight into place:
  - Claude Code: the `pact` MCP server for the project directory, plus the hooks env file.
  - Runner: its env file (mode 600) and role instructions, a clone (`--repo`), and on macOS a LaunchAgent whose `PATH` holds the `claude`, `uv`, `gh` and `git` found on that machine.
- `POST /admin/api/agents/<id>/renew` issues a fresh root mandate from the agent's role. A Runner moves to it when the old one ends, so renewing needs no restart.
- `PATCH /admin/api/agents/<id>` with any of `role_id`, `projects` and `owner` edits a hired agent.
  - A new role or new projects reissue its root mandate from the role and revoke the old ones, as below.
  - A new owner changes nothing else.
  - Its id and client never change, because the log and its mandates name them. Replace the agent instead.
- `PATCH /admin/api/humans/<id>` (owner only) changes a person's `name`, `email` or `role`, or sets `disabled`.
  - People are never deleted, because entries, mandates and projects name them. A disabled person can't sign in or act.
  - A new email unpins their sign-in, so the next sign-in with it binds again.
  - The board always keeps one active owner.
- `POST /admin/api/tasks/<id>/edit` with `title` and/or `body` corrects an open task. The log keeps the old text.
- `POST /admin/api/agents/<id>/role` with `{"role_id": …}` moves an agent to another role of its client. It gets a new root mandate from that role at once. Every root mandate it held before is revoked, so the old role's wider rights don't linger, and open tasks under them stop. Its token and connection stay.
- `POST /admin/api/agents/<id>/setup-code` gives a new setup code, e.g. for a new machine.
- Roles are managed with `GET /admin/api/roles`, `PUT /admin/api/roles/<id>` and `POST /admin/api/roles/<id>/archive`.

Agents registered before roles existed take the role their name and client point to (`runner-x`,
client runner → role runner).

## Runner

`pact-runner` lives in its own repository, [pact-runner](https://github.com/hugo8xx/pact-runner). It wakes headless
Claude Code for work delegated to a `runner` agent, since the board cannot push to anyone. It holds
`pact-connect` and the push guard too. The board side is a `runner` agent with a budget, e.g.
`pact-admin agent-register runner-web --client runner --projects web --limits '{"runs": 50, "turns": 2000}' --days 7 --by <you>`.
For a task, the budget a Runner follows is the one on the mandate delegated with that task.

## Organizations

One deployment can serve many organizations. Each one sees only its own people, projects, agents,
roles, tasks, notes, mandates and log. A person belongs to exactly one organization (`humans.org_id`),
and every Admin API call is limited to the caller's organization. An id that belongs to another
organization answers `not_found` with the same words as an id that does not exist.

- **What carries the organization:** people, projects, agents, roles, approval rules, trusted roots,
  notifications and log entries. Everything else reaches its organization through a project, agent
  or mandate. The database refuses an agent in another organization's project.
- **What stays global:** ids of people, projects and agents, because agent ids are part of MCP URLs,
  tokens and scopes. A taken id answers `id_taken`.
- **Roles:** role ids such as `chat` or `runner` repeat in every organization. New organizations
  start from `role_templates`.
- **Kill switch:** each organization has its own (`orgs.halted`), and the platform-wide
  `system_state.halted` still stops everyone.
- **Log:** entries with no project go to the organization's own chain (`orgs.system_chain`). The
  organization that existed before migration 019 keeps the `_system` chain, because a chain's key is
  part of every entry's hash.

## Admin API

`/admin/api/*` is for people, not agents: it takes an OAuth access token whose audience is
`<PACT_PUBLIC_URL>/admin`, signed in with a second factor (`amr` contains `mfa`). Agent tokens and
tokens minted for agent URLs are refused. Roles: owners do everything (kill switch, production
flag, freezing, banning, trusted roots); approvers approve tasks, register agents, issue or revoke
mandates and import credentials;
viewers read. The UI lives in its own repo, [hugo8xx/pact-admin](https://github.com/hugo8xx/pact-admin).

Before revoking, `GET /admin/api/mandates/{id}/impact` shows what would go with it (mandates below,
open tasks that get canceled, agents that lose authority) without changing anything. Resuming a
deferred task takes an optional `answer`, which the agent then sees on the task in `pact_list`.

For the credential views, `GET /admin/api/mandates` also returns each mandate's `format`,
`exported_as`, `external_id`, `issuer_principal` and `revocation_published` (some id minted for it
is on a published revocation list); `GET /admin/api/agents` returns each agent's live `keys`; and
`GET /admin/api/credentials/status` gives, per format, the revocation list's `version`, the
`revoked_count` of ids on it now and its `published_path`, plus the current `export_format`
(`PACT_EXPORT_FORMAT`, or null).

Mandates are signed and never edited. To change an agent's permissions, `POST
/admin/api/mandates/{id}/replace` with the new `scope` issues a fresh root mandate and makes it the
agent's own. With `"revoke": true` the old root and everything delegated under it go too; without
it, work already delegated under the old one carries on until it expires.

## Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | yes | Postgres connection string |
| `PACT_SIGNING_KEY` | yes | ≥ 32 random characters. Verifies mandates signed before Ed25519 and, without `PACT_BOARD_KEYS`, seeds the board's Ed25519 key |
| `PACT_BOARD_KEYS` | no | the board's Ed25519 keyring, `kid=<base64url 32-byte seed>` entries separated by commas, newest first. The first signs; all verify. `pact-admin key-new` prints an entry |
| `PACT_PUBLIC_URL` | yes in production | this server's public URL, e.g. `https://board.example.com` |
| `PACT_AUTH_ISSUER` | for the hosted Claude apps | your authorization server's issuer URL; unset = agent tokens only |
| `PACT_ADMIN_REQUIRE_MFA` | no | default `1`; set `0` only if your issuer never reports `amr` |
| `PACT_ROLE` | no | `admin` runs the Admin API service (`pact-admin-api`) instead of the board |
| `PACT_ADMIN_AUDIENCE` | Admin API service | audience of Admin API tokens; set it to `<board URL>/admin` so tokens stay the same |
| `PACT_ADMIN_API` | no | default `on`; `off` makes the board stop serving `/admin/api` once the Admin API service is live |
| `PACT_SLACK_WEBHOOK_URL` | no | a Slack incoming webhook; the process that has it delivers notifications (set it on the Admin API service only) |
| `PACT_ADMIN_UI_URL` | no | the Admin UI's URL, so a notification links to its task, e.g. `https://admin.example.com` |
| `PACT_EXPORT_FORMAT` | no | `tenuo` or `biscuit`: hand agents with a registered key an outside credential on claim; unset = none |
| `PACT_EXPORT_TTL_HOURS` | no | default `24`; the longest an exported credential an agent holds lives |
| `PORT`, `HOST` | no | default `8787`, `127.0.0.1` (`0.0.0.0` in the container) |

## Deploy on Railway

1. Create a project, add a **PostgreSQL** service.
2. Add a service from this repo. Railway builds the `Dockerfile`; `railway.json` sets the health check.
3. Set the variables above. `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`. Generate a public domain
   and put it in `PACT_PUBLIC_URL`.
4. Deploy. Migrations run on start. Then, from your machine with the same `DATABASE_URL`
   (Railway shows a public proxy URL), run the `pact-admin` commands above.
5. In Claude: *Settings → Connectors → Add custom connector* → `https://<domain>/mcp/a/<agent-id>`.
6. The Admin API runs as a second service from the same repo, so the kill switch keeps working when the
   MCP side is down: add a service from this repo with `PACT_ROLE=admin`, the same `DATABASE_URL`,
   `PACT_SIGNING_KEY` and `PACT_AUTH_ISSUER` (Railway reference variables), `PACT_ADMIN_AUDIENCE=<board URL>/admin`,
   and its own public domain in `PACT_PUBLIC_URL`. Point the Admin UI's `PACT_ADMIN_API_URL` at it, then set
   `PACT_ADMIN_API=off` on the board.

## Checks

```bash
createdb pact_test               # once; .env.test points DATABASE_URL at it
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```

The test suite drops and recreates the `public` schema of the test database on every run.

## Layout

| Path | What |
| --- | --- |
| `src/pact/board.py` | the 8 tools as plain async methods |
| `src/pact/context.py` | project context notes |
| `src/pact/mandates.py` | issuing, whole-chain verification, aggregate limits, revocation |
| `src/pact/entries.py` | append-only log, one hash chain per project, PDPA payload erasure |
| `src/pact/admin.py` | human-only operations (the Admin UI backend) |
| `src/pact/admin_server.py` | the Admin API as its own service (`pact-admin-api`) |
| `src/pact/oauth.py` | the board as an OAuth protected resource (RFC 9728, JWKS verification) |
| `src/pact/server.py` | MCP tools, `/mcp/a/<agent>` routing, agent-token and OAuth auth |
| `src/pact/credentials/` | credential adapters (`tenuo.py`, `biscuit.py`); `tests/test_credential_conformance.py` runs every format |
| `src/pact/hooks.py` | the Claude Code hook endpoints |
| `hooks/` | the hook script and a settings example |
| `src/pact/migrations/` | SQL schema |
| `tests/` | one test per done-criterion |

## License

[Apache-2.0](LICENSE)
