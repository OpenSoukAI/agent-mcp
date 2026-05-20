#!/usr/bin/env bash
# Sets up the Referrer Agent MCP servers for Claude Code.
# Run from the repo root: bash scripts/setup-mcp.sh
set -euo pipefail

SIGNER_BIN="${SIGNER_INSTALL_PATH:-$HOME/.local/bin/referrer-signer}"
MCP_URL="${REFERRER_MCP_URL:-http://localhost:8081/mcp}"

# ── 1. Build the signer binary ─────────────────────────────────────────────────
echo "Building referrer-signer..."
mkdir -p "$(dirname "$SIGNER_BIN")"
go build -trimpath -ldflags="-s -w" -o "$SIGNER_BIN" ./cmd/signer
echo "  → $SIGNER_BIN"

# ── 2. Get agent private key ───────────────────────────────────────────────────
if [ -z "${AGENT_PRIVATE_KEY:-}" ]; then
  echo ""
  echo "Your agent private key is the key you saved during wallet setup."
  echo "It is 0x followed by 64 hex characters."
  read -rsp "Paste your agent private key: " AGENT_PRIVATE_KEY
  echo ""
fi

if ! [[ "$AGENT_PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
  echo "ERROR: Invalid key format. Expected 0x + 64 hex chars."
  exit 1
fi

# ── 3. Register MCP servers via claude CLI ─────────────────────────────────────
echo "Registering MCP servers..."

# Remove first so re-runs are idempotent.
claude mcp remove --scope user referrer-agent 2>/dev/null || true
claude mcp remove --scope user referrer-signer 2>/dev/null || true

claude mcp add --scope user --transport http referrer-agent "$MCP_URL"
echo "  → referrer-agent ($MCP_URL)"

claude mcp add --scope user referrer-signer "$SIGNER_BIN" \
  -e "AGENT_PRIVATE_KEY=$AGENT_PRIVATE_KEY"
echo "  → referrer-signer ($SIGNER_BIN)"

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "Done. Two MCP servers registered (user scope — available in all projects):"
echo "  referrer-agent  (remote: $MCP_URL)"
echo "  referrer-signer (local:  $SIGNER_BIN)"
echo ""
echo "Verify with: claude mcp list"
