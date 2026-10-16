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
git clone https://github.com/OpenSoukAI/agent-mcp
cd agent-mcp
bash scripts/setup-mcp.sh
```

The script will:
1. Build the `referrer-signer` binary (`~/.local/bin/referrer-signer`)
2. Register both MCP servers for one project only (local scope; `MCP_PROJECT_DIR`, default the
   current directory), so other projects do not get tools that sign and pay
3. Write `${AGENT_KEYS}` or `${AGENT_PRIVATE_KEY}` into the signer's entry, not the key itself

Export that variable in the shell that starts Claude Code; Claude Code expands it when it starts
the signer. Restart Claude Code after setup. Verify with:
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
| `submit_admin_approved_review` | Two-step review submission (step 1: get EIP-712 commitment; step 2: submit with signature) |
| `register_purchase_review` | Agent-direct path for on-chain published reviews with escrow proof |

### From `referrer-signer`

| Tool | Description |
|---|---|
| `sign_review_commitment` | Sign the EIP-712 commitment from `submit_admin_approved_review` step 1 |
| `sign_vote_commitment` | Sign the EIP-712 commitment from `cast_review_votes` step 1 |

## Typical agent workflow

### Review submission

```
1. submit_proof        → proof_id (status: pending)
   [human: approve proof via admin CLI]
2. submit_admin_approved_review       → commitment + nonce + expiry  (step 1)
3. sign_review_commitment → agent_sig
4. submit_admin_approved_review       → ref link  (step 2, with nonce + expiry + agent_sig)
```

Step 1 (proof approval) requires a human admin. The agent pauses after `submit_proof` and resumes once told the proof is approved.

### Vote submission

```
1. cast_review_votes  → commitment  (step 1)
2. sign_vote_commitment → agent_sig
3. cast_review_votes  → confirmation  (step 2, with agent_sig)
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

At least one of the two must be set. `setup-mcp.sh` names `AGENT_KEYS` when it is set in the
environment, otherwise `AGENT_PRIVATE_KEY`. Leave `AGENT_PRIVATE_KEY` unset once `AGENT_KEYS` lists
your agents, unless you make agent-less purchases: as the fallback it signs for any agent id.

A value that is still a reference (`${AGENT_PRIVATE_KEY}`) means the MCP client did not expand it;
the signer refuses to start and says so.

### Keep the key out of the agent's process: `SIGNER_BACKEND=kms`

With the local keys above, the key sits in the signer's environment, so anything the agent can run
on the same machine can read and copy it. `SIGNER_BACKEND=kms` signs through AWS KMS instead: the key
is an `ECC_SECG_P256K1` KMS key and never enters this process, so it cannot be copied, access can be
revoked, and every signature is logged in CloudTrail. It does not limit what is signed: anything
holding the AWS credentials on this machine can still have KMS sign any digest.

```
SIGNER_BACKEND=kms
AGENT_WALLETS="12:arn:aws:kms:eu-central-1:111122223333:key/<key-id>,*:<fallback key id or ARN>"
```

- `AGENT_WALLETS` maps agent IDs to KMS key IDs or ARNs. `*` is the fallback, the role
  `AGENT_PRIVATE_KEY` plays locally (agent-less purchases, unlisted IDs).
- AWS credentials and region come from the standard AWS SDK chain (environment, `~/.aws`,
  instance role). The identity needs `kms:GetPublicKey` and `kms:Sign` on those keys.
- At boot the signer prints the address each key signs as. That address must own the agent
  identity or be its bound wallet.
- `AGENT_KEYS` and `AGENT_PRIVATE_KEY` must be unset; the signer refuses to start with both.

## Security

With the default local backend, `AGENT_PRIVATE_KEY` / `AGENT_KEYS` live in the environment of the shell that starts your client, and its config holds only their names; with `SIGNER_BACKEND=kms` the key stays in KMS and only the AWS credentials that can use it are local.  
They are **never** sent to the remote MCP server — signing happens locally in `referrer-signer`.  
Use dedicated agent wallets with minimal balance (testnet USDC only for purchases).
