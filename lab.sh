#!/usr/bin/env bash
# mcp-vuln-lab runner — plain `docker run` (no compose plugin required).
# Isolated: a private bridge network, no host volumes, ports bound to 127.0.0.1 only.
set -euo pipefail

IMAGE="mcp-vuln-lab"
NET="mcplab-net"
# name|module|port
TARGETS=(
  "mcplab-easy-mcp|easy_mcp:app|8911"
  "mcplab-easy-chat|easy_chat:app|8912"
  "mcplab-medium-mcp|medium_mcp:app|8921"
  "mcplab-medium-agent|medium_agent:app|8922"
  "mcplab-hard-mcp|hard_mcp:app|8931"
  "mcplab-hard-agent|hard_agent:app|8932"
)

here() { cd "$(dirname "$0")"; }
build() { here; docker build -t "$IMAGE" .; }

up() {
  here; build
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
  for t in "${TARGETS[@]}"; do
    IFS='|' read -r name module port <<<"$t"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --network "$NET" \
      -e MODULE="$module" -e PORT="$port" \
      -p "127.0.0.1:$port:$port" "$IMAGE" >/dev/null
    echo "  up  $name  ->  http://127.0.0.1:$port"
  done
  echo "lab is up. MCP endpoints end in /mcp (e.g. http://127.0.0.1:8911/mcp)."
}

down() {
  for t in "${TARGETS[@]}"; do
    IFS='|' read -r name _ _ <<<"$t"
    docker rm -f "$name" >/dev/null 2>&1 && echo "  down $name" || true
  done
}

ps() { docker ps --filter "name=mcplab-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"; }
logs() { docker logs -f "${1:-mcplab-easy-mcp}"; }

case "${1:-up}" in
  up) up ;;
  down) down ;;
  rebuild) down; up ;;
  ps) ps ;;
  logs) logs "${2:-}" ;;
  *) echo "usage: ./lab.sh {up|down|rebuild|ps|logs [container]}"; exit 1 ;;
esac
