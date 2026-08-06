#!/usr/bin/env bash
# Delete every case: all reports and every stored sample file.
#
#   ./reset-cases.sh              show what would be deleted, delete nothing
#   ./reset-cases.sh --yes        delete, after typed confirmation
#   ./reset-cases.sh --yes --keep-files
#                                 clear reports but leave samples on disk
#
# Works against the running Docker stack if it is up, otherwise against a local
# backend using whatever DATABASE_URL is in backend/.env.
#
# This removes evidence. It is deliberately not part of stop.sh, and it always
# shows the counts and asks before touching anything.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
say()  { printf '%s\n' "$*"; }
die()  { printf '%sx%s %s\n' "$BOLD" "$RESET" "$*" >&2; exit 1; }

CONFIRMED=0
PASSTHROUGH=()
for arg in "$@"; do
  case "$arg" in
    --yes) CONFIRMED=1 ;;
    --keep-files) PASSTHROUGH+=("--keep-files") ;;
    -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown option: $arg (try --help)" ;;
  esac
done

# Prefer the container when the stack is running: it already has the right
# DATABASE_URL and can reach Postgres, which the host usually cannot.
if docker compose ps --status running backend 2>/dev/null | grep -q backend; then
  RUN=(docker compose exec -T backend python -m scripts.reset_cases)
  say "${DIM}Target: running Docker stack${RESET}"
elif [[ -x backend/.venv/bin/python ]]; then
  # An exported DATABASE_URL wins over backend/.env, so a developer pointed at a
  # local SQLite file can reset it without editing the shared config.
  RUN=(env -C backend ./.venv/bin/python -m scripts.reset_cases)
  if [[ -n "${DATABASE_URL:-}" ]]; then
    say "${DIM}Target: local backend (DATABASE_URL from environment)${RESET}"
  else
    say "${DIM}Target: local backend (backend/.env)${RESET}"
  fi
else
  die "No running stack and no backend/.venv. Start the stack or create the venv first."
fi

# Always show the counts before asking.
"${RUN[@]}" "${PASSTHROUGH[@]}"

[[ "$CONFIRMED" == 1 ]] || exit 0

say ""
say "${BOLD}This permanently deletes every report and every stored sample.${RESET}"
say "${DIM}These may be case evidence. This cannot be undone.${RESET}"
say ""
read -r -p "Type 'reset all cases' to confirm: " reply
[[ "$reply" == "reset all cases" ]] || die "Cancelled. Nothing was deleted."

"${RUN[@]}" --yes "${PASSTHROUGH[@]}"
