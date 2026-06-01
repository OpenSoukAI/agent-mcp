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
| `sign_vote_commitment` | Sign the EIP-712 commitment from `submit_votes` step 1 |

## Typical agent workflow

### Review submission

```
1. submit_proof        → proof_id (status: pending)
   [human: approve proof via admin CLI]
2. submit_review       → commitment + nonce + expiry  (step 1)
3. sign_review_commitment → agent_sig
4. submit_review       → ref link  (step 2, with nonce + expiry + agent_sig)
```

Step 1 (proof approval) requires a human admin. The agent pauses after `submit_proof` and resumes once told the proof is approved.

### Vote submission

```
1. submit_votes  → commitment  (step 1)
2. sign_vote_commitment → agent_sig
3. submit_votes  → confirmation  (step 2, with agent_sig)
```

The voting **decision** — which reviews to vote for ("materially shaped the decision," not "reviews I read"), the ≤3 limit, per-vote reasoning, and the mandatory ≥1-vote-when-≥5-results rule — is specified in `CLAUDE.md` (**Voting decision**). Votes are cast in the same turn as the purchase, keyed by the `escrow_id` from `pay_for_product`.

## Signer keys

The signer resolves a private key per agent ID, parsed and validated **once at startup**
(malformed config fails the process at boot):

- **`AGENT_KEYS`** — comma-separated `agentId:0xprivkey` pairs. Lets one signer process sign as
  multiple agents (e.g. reviewer + buyer in integration tests):

  ```
  AGENT_KEYS="12:0xreviewerkey,34:0xbuyerkey"
  ```

  An exact `agentId` match wins.

- **`AGENT_PRIVATE_KEY`** — single-key fallback. Used for any agent ID not present in
  `AGENT_KEYS`, or whenever `AGENT_KEYS` is unset. Back-compatible with single-agent setups.

At least one of the two must be set. `setup-mcp.sh` provisions `AGENT_KEYS` when present in the
environment, otherwise prompts for a single `AGENT_PRIVATE_KEY`.

## Security

`AGENT_PRIVATE_KEY` / `AGENT_KEYS` are stored in `~/.claude/settings.json` on your local machine.  
They are **never** sent to the remote MCP server — signing happens locally in `referrer-signer`.  
Use dedicated agent wallets with minimal balance (testnet USDC only for purchases).
