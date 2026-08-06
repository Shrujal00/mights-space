#!/usr/bin/env bash
# Bring up the full stack: Postgres, the analysis backend, and the UI.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
say()  { printf '%s\n' "$*"; }
step() { printf '%s→%s %s\n' "$BOLD" "$RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$BOLD" "$RESET" "$*" >&2; }
die()  { printf '%sx%s %s\n' "$BOLD" "$RESET" "$*" >&2; exit 1; }

# Compose v2 is a docker subcommand; v1 is a separate binary.
if docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DC=(docker-compose)
else
  die "Docker Compose not found. Install Docker Desktop, or the docker-compose-plugin package."
fi

docker info >/dev/null 2>&1 || die "Docker isn't running. Start Docker and try again."

# The compose file declares env_file: ./backend/.env, so compose refuses to start
# without it — even though every key inside is optional.
if [[ ! -f backend/.env ]]; then
  step "Creating backend/.env from the template"
  cp backend/.env.example backend/.env
  warn "backend/.env has no API keys yet. Reports will still work, but every"
  warn "threat-intelligence source will show as 'Not asked' until you fill it in."
fi

# Docker binds these on the host, so anything already listening wins and the
# container fails with a confusing error. Catch it here instead.
port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1; }
for port in 8000 5173; do
  if port_busy "$port"; then
    die "Port $port is already in use. Stop whatever is on it (a local dev server?) and retry."
  fi
done

step "Building and starting containers"
"${DC[@]}" up -d --build

step "Waiting for the analysis service"
for _ in $(seq 1 90); do
  if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 2
done

if [[ "${ready:-}" != 1 ]]; then
  warn "The backend didn't answer in time. Recent logs:"
  "${DC[@]}" logs --tail 40 backend >&2
  die "Startup failed."
fi

# Compiling 750 YARA rule files takes a moment on first boot, so report what
# actually loaded rather than just claiming success.
health=$(curl -s http://localhost:8000/api/health)
python3 - "$health" <<'PY' 2>/dev/null || say "$health"
import json, sys
h = json.loads(sys.argv[1])
mode = "air-gapped (no network lookups)" if h["offline_mode"] else "connected to threat intelligence"
print(f"  signatures loaded : {h['yara_rules_loaded']}")
if h["yara_rules_skipped"]:
    print(f"  signatures skipped: {h['yara_rules_skipped']}")
print(f"  mode              : {mode}")
PY

step "Waiting for the interface"
for _ in $(seq 1 90); do
  curl -sf -o /dev/null http://localhost:5173/ 2>/dev/null && break
  sleep 2
done

say ""
say "${BOLD}Ready.${RESET}"
say "  Interface  http://localhost:5173"
say "  API        http://localhost:8000/api/health"
say "  Docs       http://localhost:8000/docs"
say ""
say "${DIM}Logs:  ${DC[*]} logs -f backend${RESET}"
say "${DIM}Stop:  ./stop.sh${RESET}"
