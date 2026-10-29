#!/usr/bin/env bash
# Sets up the OpenSouk MCP servers for Claude Code.
# Run from the repo root: bash scripts/setup-mcp.sh
#
# Both servers are registered for ONE project (local scope), MCP_PROJECT_DIR, so other projects
# do not get tools that sign and pay. The key goes in ~/.config/opensouk/signer.env, which the
# signer reads at startup, so it never lands in ~/.claude.json and needs no export.
set -euo pipefail

MCP_PROJECT_DIR="${MCP_PROJECT_DIR:-$PWD}"

SIGNER_BIN="${SIGNER_INSTALL_PATH:-$HOME/.local/bin/opensouk-signer}"
MCP_URL="${REFERRER_MCP_URL:-http://localhost:8081/mcp}"
BASE_RPC_URL="${BASE_RPC_URL:-https://sepolia.base.org}"
# PROTOCOL_ADDRESS_REGISTRY (optional): overrides the signer's built-in registry for CHAIN_ID.
# The signer resolves every contract address from the registry itself; nothing is looked up here.
PAR_ADDR="${PROTOCOL_ADDRESS_REGISTRY:-}"
CHAIN_ID="${CHAIN_ID:-84532}"
# AGENT_KEYS: comma-separated agentId:0xprivkey pairs to sign as multiple agents in one signer
#   process, e.g. AGENT_KEYS="12:0xabc...,34:0xdef..." (reviewer 12 + buyer 34). Otherwise
#   AGENT_PRIVATE_KEY, a single key. Written to signer.env only if that file does not exist yet.
AGENT_KEYS="${AGENT_KEYS:-}"

# ── 1. Build the signer binary ─────────────────────────────────────────────────
echo "Building opensouk-signer..."
mkdir -p "$(dirname "$SIGNER_BIN")"
go build -trimpath -ldflags="-s -w" -o "$SIGNER_BIN" ./cmd/signer
echo "  → $SIGNER_BIN"

# ── 2. The signer's key file ───────────────────────────────────────────────────
# An existing file is never changed. The signer parses and validates the keys at boot.
ENV_FILE="$HOME/.config/opensouk/signer.env"
PLACEHOLDER=""
if [ -f "$ENV_FILE" ]; then
  echo "Keeping $ENV_FILE as it is."
  if [ -n "$AGENT_KEYS" ] || [ -n "${AGENT_PRIVATE_KEY:-}" ]; then
    echo "  The key in this shell was NOT written; edit that file to change the key."
  fi
else
  if [ -n "$AGENT_KEYS" ]; then
    KEY_LINE="AGENT_KEYS=$AGENT_KEYS"
  elif [ -n "${AGENT_PRIVATE_KEY:-}" ]; then
    if ! [[ "$AGENT_PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]]; then
      echo "ERROR: AGENT_PRIVATE_KEY is not 0x + 64 hex chars."
      exit 1
    fi
    KEY_LINE="AGENT_PRIVATE_KEY=$AGENT_PRIVATE_KEY"
  else
    KEY_LINE="AGENT_PRIVATE_KEY=REPLACE_WITH_AGENT_KEY"
    PLACEHOLDER=1
  fi
  mkdir -p "$(dirname "$ENV_FILE")"
  (umask 077 && printf '%s\n' "$KEY_LINE" > "$ENV_FILE")
  echo "Wrote $ENV_FILE (mode 600)."
fi

# ── 3. Register MCP servers via claude CLI ─────────────────────────────────────
echo "Registering MCP servers..."

cd "$MCP_PROJECT_DIR"

# Remove first so re-runs are idempotent. The user-scope removals clean up what earlier versions
# of this script registered: a user-scope entry is in every project and held the key itself.
for scope in user local; do
  claude mcp remove --scope "$scope" opensouk-agent 2>/dev/null || true
  claude mcp remove --scope "$scope" opensouk-signer 2>/dev/null || true
done

claude mcp add --scope local --transport http opensouk-agent "$MCP_URL"
echo "  → opensouk-agent ($MCP_URL)"

SIGNER_ENV=(-e "BASE_RPC_URL=$BASE_RPC_URL" -e "CHAIN_ID=$CHAIN_ID")
if [ -n "$PAR_ADDR" ]; then
  SIGNER_ENV+=(-e "PROTOCOL_ADDRESS_REGISTRY=$PAR_ADDR")
fi
echo "  → opensouk-signer ($SIGNER_BIN) [key from $ENV_FILE]"

claude mcp add --scope local opensouk-signer "$SIGNER_BIN" "${SIGNER_ENV[@]}"

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "Done. Two MCP servers registered for $MCP_PROJECT_DIR only (local scope):"
echo "  opensouk-agent  (remote: $MCP_URL)"
echo "  opensouk-signer (local:  $SIGNER_BIN)"
echo "    CHAIN_ID=$CHAIN_ID"
echo ""
if [ -n "$PLACEHOLDER" ]; then
  echo "Edit $ENV_FILE: replace REPLACE_WITH_AGENT_KEY with your key."
fi
echo "Verify with: claude mcp list"
