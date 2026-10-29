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
3. Create `~/.config/opensouk/signer.env` (mode 600) if it does not exist, with `AGENT_KEYS` or
   `AGENT_PRIVATE_KEY` from your shell, or a placeholder to replace; an existing file is left as
   it is. The signer reads it at startup, so the key is not in the client config

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

### Settings file: `~/.config/opensouk/signer.env`

At startup the signer reads `KEY=value` lines from `~/.config/opensouk/signer.env`, or from the
path in `SIGNER_ENV_FILE`, so the key does not have to sit in the client's config or in a shell
export. Any setting goes there, for any backend: `AGENT_PRIVATE_KEY` or `AGENT_KEYS`, or
`SIGNER_BACKEND`, `AGENT_WALLETS` and the Turnkey, Privy or CDP credentials.

```bash
mkdir -p ~/.config/opensouk
install -m 600 /dev/null ~/.config/opensouk/signer.env
# then edit it: AGENT_PRIVATE_KEY=0x...
```

- A value the MCP client sets wins. The file fills only settings the client leaves unset, empty,
  or as a `${VAR}` reference it did not expand, and the boot log names any setting set in both.
- The signer refuses to start if the file is open to other users (`chmod 600` it), if a line is
  not `KEY=value`, or if a setting appears twice. Errors name the line, never its contents.
- `# comments`, blank lines, a leading `export ` and one pair of quotes around a value are
  accepted. Nothing is expanded.
- A missing default file is skipped; a missing `SIGNER_ENV_FILE` is an error.

### macOS Keychain

On macOS the signer also looks in the login Keychain for the secret settings: `AGENT_PRIVATE_KEY`,
`AGENT_KEYS`, `TURNKEY_API_PRIVATE_KEY`, `PRIVY_APP_SECRET` and `PRIVY_AUTHORIZATION_KEY`. Each
is a generic password under the service `opensouk-signer`, with the setting's name as the account.
Store one in your own terminal; with `-w` last, `security` prompts for the value, which keeps it
out of your shell history and the process list:

```bash
security add-generic-password -U -s opensouk-signer -a AGENT_PRIVATE_KEY -w
```

- The Keychain fills only what the MCP client and `signer.env` leave unset, and the boot log names
  any setting found in both.
- The signer reads items through `/usr/bin/security`, so an item that command created is read
  without a dialog. That also means anything running as you, the agent included, can read it the
  same way: it keeps the key encrypted at rest, not away from the agent. For that, use a remote
  backend below.
- If a read fails (a locked Keychain over SSH, or an access dialog left unanswered for 20 seconds),
  the signer logs why, stops reading the Keychain and starts from its other settings.
- Other platforms never touch the Keychain.

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

### Let a policy decide what is signed: `SIGNER_BACKEND=turnkey`, `privy` or `cdp`

KMS keeps the key out of reach but signs any digest it is given. Turnkey, Privy and CDP keep the
key too, and each request goes to them as EIP-712 typed data or a whole transaction, so their
policy engine can refuse anything outside
[the OpenSouk policy](docs/signer-policies/README.md): the eight commitment types and
`AgentWalletSet` in their own domains, `ReceiveWithAuthorization` to the SplitRouter up to a
ceiling, and the ten contract functions the transaction tools call. The signer never asks any
provider for a raw-hash signature, and the policy denies one: a raw hash can be any signature.

You create the wallet under your own provider account; OpenSouk never holds a provider
credential. `AGENT_WALLETS` maps agent IDs to the provider's wallet, `*` for the fallback.

| | Turnkey | Privy | CDP |
|---|---|---|---|
| `AGENT_WALLETS` entry | `12:<wallet account address>` | `12:<wallet id>` | `12:<wallet address>` |
| Credentials | `TURNKEY_ORG_ID`, `TURNKEY_API_PUBLIC_KEY`, `TURNKEY_API_PRIVATE_KEY` (hex P-256) | `PRIVY_APP_ID`, `PRIVY_APP_SECRET`, `PRIVY_AUTHORIZATION_KEY` (`wallet-auth:…`) | `CDP_API_KEY_ID`, `CDP_API_KEY_SECRET` (Ed25519 Secret API key; legacy EC keys refused), `CDP_WALLET_SECRET`, optional `CDP_API_BASE_URL` (default `https://api.cdp.coinbase.com/platform`) |
| The API key must belong to | a **non-root** user (root bypasses every policy) | an **additional signer**, not the wallet's owner (an owner can replace the policy) | a key with **neither** the "Export (export private key)" nor the "Manage (modify policies)" scope (see docs/signer-policies) |
| Checked at boot | the API key, with `whoami` | the wallet exists and has an owner | each wallet's policy answers "reject" to five probe requests via CDP's policy simulator — any other answer refuses boot (see docs/signer-policies) |
| Merchant REST tools | unavailable: Turnkey can personal-sign only as a raw payload | work: `personal_sign` of binary messages (any; do not make the wallet a Safe owner) | unavailable: CDP signs messages only as text, and raw bytes only through its unrestrictable sign-hash endpoint |

CDP wallets are EOA server wallets only (no smart accounts). `CDP_API_KEY_SECRET` and
`CDP_WALLET_SECRET` can live in the macOS Keychain like the other secrets.

Generate the policy with `referrer-signer policy --provider turnkey|privy|cdp`. For Privy,
`referrer-signer privy-setup` then creates the policy, the wallet and the signer entry with your
owner key, which you keep off the agent's machine. For CDP, paste the generated JSON into the CDP
portal as an account-scoped policy. See [docs/signer-policies](docs/signer-policies/README.md).

To bind a provider wallet to an identity, list the agent ID in `AGENT_WALLETS` and in the policy
(`--agent-id`), call `sign_agent_wallet_set` with it, then send `setAgentWallet` from the owner
wallet with the returned signature within five minutes.
A bound agent wallet is also where payouts go (`SplitRouter._resolveWallet`), so a provider
wallet bound to an identity receives its earnings until the owner rebinds it. Until the backend
accepts the bound wallet for signed requests (REF-491), the provider wallet must be the identity's
owner.

## Security

With the default local backend, `AGENT_PRIVATE_KEY` / `AGENT_KEYS` live in the signer's settings file or the environment of the shell that starts your client, not in the client's config; with `SIGNER_BACKEND=kms` the key stays in KMS and only the AWS credentials that can use it are local.  
They are **never** sent to the remote MCP server — signing happens locally in `referrer-signer`.  
Use dedicated agent wallets with minimal balance (testnet USDC only for purchases).
