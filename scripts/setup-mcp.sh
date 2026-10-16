#!/usr/bin/env bash
# Sets up the Referrer Agent MCP servers for Claude Code.
# Run from the repo root: bash scripts/setup-mcp.sh
#
# Both servers are registered for ONE project (local scope), MCP_PROJECT_DIR, so other projects
# do not get tools that sign and pay. The signer's entry names AGENT_KEYS / AGENT_PRIVATE_KEY
# instead of holding the key: Claude Code expands the reference when it starts the signer, so
# export the variable in the shell that starts `claude`. The key never lands in ~/.claude.json.
set -euo pipefail

MCP_PROJECT_DIR="${MCP_PROJECT_DIR:-$PWD}"

SIGNER_BIN="${SIGNER_INSTALL_PATH:-$HOME/.local/bin/referrer-signer}"
MCP_URL="${REFERRER_MCP_URL:-http://localhost:8081/mcp}"
BASE_RPC_URL="${BASE_RPC_URL:-https://sepolia.base.org}"
# PROTOCOL_ADDRESS_REGISTRY (optional): overrides the signer's built-in registry for CHAIN_ID.
# The signer resolves every contract address from the registry itself; nothing is looked up here.
PAR_ADDR="${PROTOCOL_ADDRESS_REGISTRY:-}"
CHAIN_ID="${CHAIN_ID:-84532}"
# AGENT_KEYS: comma-separated agentId:0xprivkey pairs to sign as multiple agents in one signer
#   process, e.g. AGENT_KEYS="12:0xabc...,34:0xdef..." (reviewer 12 + buyer 34). Otherwise
#   AGENT_PRIVATE_KEY, a single key. Only the variable's name is written to the config.
AGENT_KEYS="${AGENT_KEYS:-}"

# ── 1. Build the signer binary ─────────────────────────────────────────────────
echo "Building referrer-signer..."
mkdir -p "$(dirname "$SIGNER_BIN")"
go build -trimpath -ldflags="-s -w" -o "$SIGNER_BIN" ./cmd/signer
echo "  → $SIGNER_BIN"

# ── 2. Which key variable the signer reads ─────────────────────────────────────
# The signer parses and validates the keys at boot; here we only pick the variable to name.
if [ -n "$AGENT_KEYS" ]; then
  KEY_VAR=AGENT_KEYS
elif [ -n "${AGENT_PRIVATE_KEY:-}" ]; then
  KEY_VAR=AGENT_PRIVATE_KEY
  if ! [[ "$AGENT_PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
    echo "ERROR: AGENT_PRIVATE_KEY is not 0x + 64 hex chars."
    exit 1
  fi
else
  KEY_VAR=AGENT_PRIVATE_KEY
  echo ""
  echo "WARNING: neither AGENT_KEYS nor AGENT_PRIVATE_KEY is set in this shell. The signer will"
  echo "  refuse to start until you export one in the shell that starts Claude Code."
fi

# ── 3. Register MCP servers via claude CLI ─────────────────────────────────────
echo "Registering MCP servers..."

cd "$MCP_PROJECT_DIR"

# Remove first so re-runs are idempotent. The user-scope removals clean up what earlier versions
# of this script registered: a user-scope entry is in every project and held the key itself.
for scope in user local; do
  claude mcp remove --scope "$scope" referrer-agent 2>/dev/null || true
  claude mcp remove --scope "$scope" referrer-signer 2>/dev/null || true
done

claude mcp add --scope local --transport http referrer-agent "$MCP_URL"
echo "  → referrer-agent ($MCP_URL)"

SIGNER_ENV=(-e "BASE_RPC_URL=$BASE_RPC_URL" -e "CHAIN_ID=$CHAIN_ID")
if [ -n "$PAR_ADDR" ]; then
  SIGNER_ENV+=(-e "PROTOCOL_ADDRESS_REGISTRY=$PAR_ADDR")
fi
# The \$ is escaped, so the config gets the reference "${VAR}", not the key.
SIGNER_ENV+=(-e "$KEY_VAR=\${$KEY_VAR}")
echo "  → referrer-signer ($SIGNER_BIN) [key from \$$KEY_VAR]"

claude mcp add --scope local referrer-signer "$SIGNER_BIN" "${SIGNER_ENV[@]}"

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "Done. Two MCP servers registered for $MCP_PROJECT_DIR only (local scope):"
echo "  referrer-agent  (remote: $MCP_URL)"
echo "  referrer-signer (local:  $SIGNER_BIN)"
echo "    CHAIN_ID=$CHAIN_ID"
echo ""
echo "Export $KEY_VAR in the shell that starts Claude Code, then verify with: claude mcp list"
