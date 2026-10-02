#!/bin/sh
# PACT Board hook for Claude Code. Forwards the hook's stdin JSON to the board.
#
#   pact-hook.sh <agent-id> post-tool-use        # log a shell command or file edit on the task in hand
#   pact-hook.sh <agent-id> stop                 # tell the person about new tasks; never claims
#   pact-hook.sh <agent-id> session-start        # show the open tasks when a session opens; never claims
#   pact-hook.sh <agent-id> user-prompt-submit   # auto-claim one delegated task, only if every condition holds
#
# Reads PACT_URL and PACT_TOKEN from ${PACT_HOOK_DIR:-~/.config/pact}/<agent-id>.env, kept
# outside the repo. Auto-claim also reads, from the same file:
#   PACT_AUTO_CLAIM=1                       turn it on (off unless set; set it per agent/repo)
#   PACT_AUTO_CLAIM_FROM=chat-alice,...     senders whose delegated tasks may be claimed
# and checks that the working tree is clean. Missing config or an unreachable board never
# blocks Claude Code: the hook prints nothing and exits 0.

agent="$1"
event="$2"
conf="${PACT_HOOK_DIR:-$HOME/.config/pact}/$agent.env"
[ -n "$agent" ] && [ -n "$event" ] && [ -r "$conf" ] || exit 0
. "$conf"
[ -n "$PACT_URL" ] && [ -n "$PACT_TOKEN" ] || exit 0

# Clean = no uncommitted or staged changes. A session opened in a folder that holds several repos
# (not a repo itself) counts as clean only when it holds at least one repo and every one is clean.
clean=0
if [ "$event" = "user-prompt-submit" ]; then
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    [ -z "$(git status --porcelain 2>/dev/null)" ] && clean=1
  else
    found=0
    clean=1
    for d in */; do
      [ -d "$d.git" ] || continue
      found=1
      [ -z "$(git -C "$d" status --porcelain 2>/dev/null)" ] || clean=0
    done
    [ "$found" = 1 ] || clean=0
  fi
fi

out=$(curl -sS -m 5 -X POST \
  -H "Authorization: Bearer $PACT_TOKEN" -H "Content-Type: application/json" \
  -H "X-Pact-Auto-Claim: ${PACT_AUTO_CLAIM:-0}" \
  -H "X-Pact-Auto-Claim-From: ${PACT_AUTO_CLAIM_FROM:-}" \
  -H "X-Pact-Git-Clean: $clean" \
  --data-binary @- "$PACT_URL/hooks/a/$agent/$event" 2>/dev/null) || exit 0

# The post-tool-use receipt stays quiet; the other events answer in hook output format.
[ "$event" != "post-tool-use" ] && printf '%s\n' "$out"
exit 0
