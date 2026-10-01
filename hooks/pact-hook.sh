#!/bin/sh
# PACT Board hook for Claude Code. Forwards the hook's stdin JSON to the board.
#
#   pact-hook.sh <agent-id> post-tool-use   # log a shell command or file edit on the task in hand
#   pact-hook.sh <agent-id> stop            # tell the person about new tasks; never claims
#
# Reads PACT_URL and PACT_TOKEN from ${PACT_HOOK_DIR:-~/.config/pact}/<agent-id>.env, kept
# outside the repo. Missing config or an unreachable board never blocks Claude Code: the
# hook prints nothing and exits 0.

agent="$1"
event="$2"
conf="${PACT_HOOK_DIR:-$HOME/.config/pact}/$agent.env"
[ -n "$agent" ] && [ -n "$event" ] && [ -r "$conf" ] || exit 0
. "$conf"
[ -n "$PACT_URL" ] && [ -n "$PACT_TOKEN" ] || exit 0

out=$(curl -sS -m 5 -X POST \
  -H "Authorization: Bearer $PACT_TOKEN" -H "Content-Type: application/json" \
  --data-binary @- "$PACT_URL/hooks/a/$agent/$event" 2>/dev/null) || exit 0

# Only the Stop answer is hook output; the post-tool-use receipt stays quiet.
[ "$event" = "stop" ] && printf '%s\n' "$out"
exit 0
