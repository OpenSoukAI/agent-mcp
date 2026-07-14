#!/usr/bin/env bash
# Sets up the Referrer Agent MCP servers for Claude Code.
# Run from the repo root: bash scripts/setup-mcp.sh
set -euo pipefail

SIGNER_BIN="${SIGNER_INSTALL_PATH:-$HOME/.local/bin/referrer-signer}"
MCP_URL="${REFERRER_MCP_URL:-http://localhost:8081/mcp}"
BASE_RPC_URL="${BASE_RPC_URL:-https://sepolia.base.org}"
PAR_ADDR="${PROTOCOL_ADDRESS_REGISTRY:-0xd1A08383dcC7E74c2F94c94931BdFCff2508137D}"
CHAIN_ID="${CHAIN_ID:-84532}"
# AGENT_KEYS (optional): comma-separated agentId:0xprivkey pairs to sign as multiple agents
#   in one signer process, e.g. AGENT_KEYS="12:0xabc...,34:0xdef..." (reviewer 12 + buyer 34).
#   If unset, falls back to single-key AGENT_PRIVATE_KEY.
AGENT_KEYS="${AGENT_KEYS:-}"

# ── 1. Build the signer binary ─────────────────────────────────────────────────
echo "Building referrer-signer..."
mkdir -p "$(dirname "$SIGNER_BIN")"
go build -trimpath -ldflags="-s -w" -o "$SIGNER_BIN" ./cmd/signer
echo "  → $SIGNER_BIN"

# ── 2. Get agent key(s) ────────────────────────────────────────────────────────
# Multi-key mode (AGENT_KEYS) skips the single-key prompt entirely; the signer
# parses + validates each AGENT_KEYS entry at boot.
if [ -z "$AGENT_KEYS" ]; then
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
fi

# ── 3. Resolve ReviewRegistry address from ProtocolAddressRegistry ────────────
echo "Resolving ReviewRegistry address from PAR ($PAR_ADDR)..."
if ! command -v cast &>/dev/null; then
  echo "ERROR: 'cast' (Foundry) is required to resolve contract addresses. Install from https://getfoundry.sh"
  exit 1
fi

REVIEW_REGISTRY_KEY=$(cast keccak "REVIEW_REGISTRY")
REVIEW_REGISTRY_ADDRESS=$(cast call --rpc-url "$BASE_RPC_URL" "$PAR_ADDR" \
  "getAddress(bytes32)(address)" "$REVIEW_REGISTRY_KEY")

if [ "$REVIEW_REGISTRY_ADDRESS" = "0x0000000000000000000000000000000000000000" ]; then
  echo "ERROR: ReviewRegistry address is zero in PAR. Has it been deployed and registered?"
  exit 1
fi
echo "  → REVIEW_REGISTRY_ADDRESS=$REVIEW_REGISTRY_ADDRESS"

# ── 3b. Resolve CommissionEscrow address from ProtocolAddressRegistry ─────────
# PAR key is "ESCROW" (see ProtocolAddressRegistry.sol), not "COMMISSION_ESCROW".
echo "Resolving CommissionEscrow address from PAR ($PAR_ADDR)..."
ESCROW_KEY=$(cast keccak "ESCROW")
COMMISSION_ESCROW_ADDRESS=$(cast call --rpc-url "$BASE_RPC_URL" "$PAR_ADDR" \
  "getAddress(bytes32)(address)" "$ESCROW_KEY")

if [ "$COMMISSION_ESCROW_ADDRESS" = "0x0000000000000000000000000000000000000000" ]; then
  echo "ERROR: CommissionEscrow address is zero in PAR. Has it been deployed and registered?"
  exit 1
fi
echo "  → COMMISSION_ESCROW_ADDRESS=$COMMISSION_ESCROW_ADDRESS"

# ── 4. Register MCP servers via claude CLI ─────────────────────────────────────
echo "Registering MCP servers..."

# Remove first so re-runs are idempotent.
claude mcp remove --scope user referrer-agent 2>/dev/null || true
claude mcp remove --scope user referrer-signer 2>/dev/null || true

claude mcp add --scope user --transport http referrer-agent "$MCP_URL"
echo "  → referrer-agent ($MCP_URL)"

SIGNER_ENV=(-e "BASE_RPC_URL=$BASE_RPC_URL" -e "REVIEW_REGISTRY_ADDRESS=$REVIEW_REGISTRY_ADDRESS" -e "COMMISSION_ESCROW_ADDRESS=$COMMISSION_ESCROW_ADDRESS" -e "CHAIN_ID=$CHAIN_ID")
if [ -n "$AGENT_KEYS" ]; then
  SIGNER_ENV+=(-e "AGENT_KEYS=$AGENT_KEYS")
  echo "  → referrer-signer ($SIGNER_BIN) [multi-key: AGENT_KEYS]"
else
  SIGNER_ENV+=(-e "AGENT_PRIVATE_KEY=$AGENT_PRIVATE_KEY")
  echo "  → referrer-signer ($SIGNER_BIN) [single-key: AGENT_PRIVATE_KEY]"
fi

claude mcp add --scope user referrer-signer "$SIGNER_BIN" "${SIGNER_ENV[@]}"

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo "Done. Two MCP servers registered (user scope — available in all projects):"
echo "  referrer-agent  (remote: $MCP_URL)"
echo "  referrer-signer (local:  $SIGNER_BIN)"
echo "    REVIEW_REGISTRY_ADDRESS=$REVIEW_REGISTRY_ADDRESS"
echo "    COMMISSION_ESCROW_ADDRESS=$COMMISSION_ESCROW_ADDRESS"
echo "    CHAIN_ID=$CHAIN_ID"
echo ""
echo "Verify with: claude mcp list"
