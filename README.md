# Referrer Agent — MCP Setup

Connects Claude Code (or any MCP-compatible AI agent) to the Referrer Agent protocol.

Two MCP servers are registered:

| Server | Type | Purpose |
|---|---|---|
| `referrer-agent` | HTTP | Protocol tools: query reviews, submit proofs, submit reviews, register ref links |
| `referrer-signer` | stdio | Signs EIP-712 ReviewCommitment with your agent private key |

## Prerequisites

- Go 1.21+
- Python 3 (for the setup script — ships with macOS and most Linux distros)
- Claude Code CLI (`claude`)
- An agent identity NFT and private key (get one at the [wallet setup page](https://app.referrer-agent.io/wallet-setup))

## Setup

```bash
git clone https://github.com/Ref-Agent/agent-mcp
cd agent-mcp
bash scripts/setup-mcp.sh
```

The script will:
1. Build the `referrer-signer` binary (`~/.local/bin/referrer-signer`)
2. Ask for your agent private key (stored only in `~/.claude/settings.json`, never committed)
3. Register both MCP servers in your Claude Code config

Restart Claude Code after setup. Verify with:
```bash
claude mcp list
```

### Custom MCP URL

By default the setup script points to `http://localhost:8081/mcp` (local backend).
To use a deployed instance:

```bash
REFERRER_MCP_URL=https://mcp.referrer-agent.io/mcp bash scripts/setup-mcp.sh
```

### Custom install path

```bash
SIGNER_INSTALL_PATH=/usr/local/bin/referrer-signer bash scripts/setup-mcp.sh
```

## Available tools

After setup, your agent has access to:

### From `referrer-agent`

| Tool | Description |
|---|---|
| `query_registry` | Search published reviews for a merchant product |
| `fetch_review` | Fetch a single review by on-chain review ID |
| `submit_proof` | Submit off-chain purchase proof (requires admin approval before review) |
| `submit_review` | Two-step review submission (step 1: get EIP-712 commitment; step 2: submit with signature) |
| `register_published_review` | Agent-direct path for on-chain published reviews with escrow proof |

### From `referrer-signer`

| Tool | Description |
|---|---|
| `sign_review_commitment` | Sign the EIP-712 commitment from `submit_review` step 1 |

## Typical agent workflow

```
1. submit_proof        → proof_id (status: pending)
   [human: approve proof via admin CLI]
2. submit_review       → commitment + nonce + expiry  (step 1)
3. sign_review_commitment → agent_sig
4. submit_review       → ref link  (step 2, with nonce + expiry + agent_sig)
```

Step 1 (proof approval) requires a human admin. The agent pauses after `submit_proof` and resumes once told the proof is approved.

## Security

`AGENT_PRIVATE_KEY` is stored in `~/.claude/settings.json` on your local machine.  
It is **never** sent to the remote MCP server — signing happens locally in `referrer-signer`.  
Use a dedicated agent wallet with minimal balance (testnet USDC only for purchases).
