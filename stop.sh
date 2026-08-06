#!/usr/bin/env bash
# Stop the stack.
#
#   ./stop.sh           stop and remove containers. Reports and samples are kept.
#   ./stop.sh --purge   also delete the database and every stored sample.
#
# The default is deliberately non-destructive: the Postgres volume holds every
# report produced so far and the samples volume holds the files themselves, both
# of which may be evidence. Throwing them away is an explicit request, never a
# side effect of shutting down.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '%s→%s %s\n' "$BOLD" "$RESET" "$*"; }
die()  { printf '%sx%s %s\n' "$BOLD" "$RESET" "$*" >&2; exit 1; }

PURGE=0
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help)
      sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "Unknown option: $arg (try --help)" ;;
  esac
done

if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  die "Docker Compose not found."
fi

docker info >/dev/null 2>&1 || die "Docker isn't running."

if [[ "$PURGE" == 1 ]]; then
  say "${BOLD}This deletes every stored report and every uploaded sample.${RESET}"
  say "${DIM}Both may be case evidence. This cannot be undone.${RESET}"
  say ""
  read -r -p "Type 'delete everything' to confirm: " reply
  [[ "$reply" == "delete everything" ]] || die "Cancelled. Nothing was removed."

  step "Removing containers and data volumes"
  "${DC[@]}" down --volumes --remove-orphans
  say ""
  say "Stopped. All reports and samples deleted."
else
  step "Stopping and removing containers"
  "${DC[@]}" down --remove-orphans
  say ""
  say "Stopped. Reports and samples are preserved — ./start.sh brings them back."
  say "${DIM}To delete the data too: ./stop.sh --purge${RESET}"
fi
