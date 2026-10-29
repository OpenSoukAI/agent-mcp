# Signer policies (Turnkey, Privy, CDP)

With `SIGNER_BACKEND=turnkey`, `privy` or `cdp`, the agent's key lives with the provider, and the
provider's policy decides what it signs. These files are that policy, version 2:

| File | Provider | Applied as |
|---|---|---|
| `turnkey.v2.json` | Turnkey | one policy per entry in `policies` |
| `privy.v2.json` | Privy | one policy, attached to the wallet |
| `cdp.v2.json` | CDP | one account-scoped policy, assigned to the account |

Version 1 (`*.v1.json`) lacks `AgentWalletSet`, so a wallet on it cannot be bound with
`sign_agent_wallet_set`. Apply v2 in its place. CDP has no v1.

All three allow exactly:

- the eight commitment types the signer tools sign, each only in its own EIP-712 domain, on the
  configured chain, with the protocol contract as `verifyingContract`;
- `AgentWalletSet` on the IdentityRegistry, only for the agent ids given with `--agent-id`, which
  `sign_agent_wallet_set` signs so the identity's owner can bind this wallet. Bound to any other
  identity, this wallet's payments would count as that identity's receipts. Without `--agent-id`
  the policy allows no `AgentWalletSet`;
- `ReceiveWithAuthorization` (ERC-3009) on USDC, only to the SplitRouter, and only up to the
  payment ceiling;
- transactions with no ETH value, each only to one function a signer tool calls on the
  ReviewRegistry, CommissionEscrow, MerchantRegistry or ProductRegistry (ten in all);
- on Privy, `personal_sign` of binary messages, which the merchant REST tools authenticate with
  (a 32-byte hash). Text, such as a sign-in message for another site, is denied: Privy evaluates
  message conditions only on valid UTF-8, so a DENY on any text leaves binary messages. The
  EIP-191 prefix keeps a personal signature from passing as a typed-data or transaction
  signature, but any binary message is still signed, including a 32-byte hash that a contract
  checking EIP-191 signatures would accept, such as a Safe owner's `eth_sign` approval.
  OpenSouk's contracts check none. Do not make this wallet a Safe owner or a signer for any
  contract that does. Turnkey and CDP have no equivalent their policy can inspect, so the
  merchant REST tools are unavailable on either (CDP: see below).

Everything else is denied. On Turnkey, raw payloads that are not EIP-712 are denied explicitly: a
raw hash can be any typed-data or transaction signature, so allowing one would void the rest. On
CDP, five operations are rejected explicitly — `signEvmHash`, `signEvmMessage`,
`sendEvmTransaction`, `prepareUserOperation`, `sendUserOperation` — because CDP allows by default
any operation no rule names; trimming these rejects would silently allow them.

## Make the policy for your chain

The committed files carry placeholders (`<CHAIN_ID>`, `<REVIEW_REGISTRY>`, `<USDC>`,
`<MAX_PAYMENT>`, `<TURNKEY_SIGNER_USER_ID>`, ...). Generate the real one with the signer's own
configuration, which resolves the contract addresses the same way the tools do:

```bash
CHAIN_ID=84532 BASE_RPC_URL=… referrer-signer policy --provider privy \
  --usdc 0x036CbD53842c5426634e7929541eC2318f3dCF7e --max-payment 5000000 --agent-id 12 > privy-policy.json

CHAIN_ID=84532 BASE_RPC_URL=… referrer-signer policy --provider turnkey \
  --usdc 0x036CbD53842c5426634e7929541eC2318f3dCF7e --max-payment 5000000 \
  --turnkey-user-id <signer user id> --wallet <wallet account address> --agent-id 12 \
  > turnkey-policies.json

CHAIN_ID=84532 BASE_RPC_URL=… referrer-signer policy --provider cdp \
  --usdc 0x036CbD53842c5426634e7929541eC2318f3dCF7e --max-payment 5000000 --agent-id 12 \
  > cdp-policy.json
```

`--max-payment` defaults to `MAX_PAYMENT_PER_TX`. One of them is required. `--agent-id` takes a
comma-separated list.

## Apply it

**Turnkey.** Sign in as the root user and create each entry of `policies` (Policies → Create
policy) with its effect, consensus and condition. Every ALLOW is scoped to the signer user and to
the one wallet account. The signer's API key must belong to a **non-root** user: root users
bypass every policy.

**Privy.** The wallet needs an owner (a key quorum you keep off the agent's machine), and the
signer's authorization key must be an **additional signer** with this policy, not the owner: an
owner can replace the policy. `referrer-signer privy-setup` creates the policy, the wallet and the
signer entry from your owner key in one go. The signer refuses to start against a wallet with no
owner.

**CDP.** In the CDP portal, go to the Server Wallet, open Policies, and create a new policy with
scope `account`, pasting in the generated JSON unchanged. Assign it to the account. Keep the
project-level policy empty, or reject-only: a project-level policy's decision overrides the
account policy, and boot refuses to start otherwise (see below). See below for what else to set
up.

## Changing a policy

Regenerate the templates after any change to a commitment type, its domain or the contracts:

```bash
go run ./cmd/signer policy --provider turnkey --template > docs/signer-policies/turnkey.v2.json
go run ./cmd/signer policy --provider privy --template > docs/signer-policies/privy.v2.json
go run ./cmd/signer policy --provider cdp --template > docs/signer-policies/cdp.v2.json
```

`TestPolicyTemplatesAreGolden` fails until you do. A change that existing deployments must
re-apply is a new version: add `*.v2.json` and keep v1 until no wallet uses it.

## CDP: what the policy cannot do, and what you must set up

The policy is weaker than Turnkey's or Privy's in two ways: CDP's typed-data rules can pin only
`verifyingContract` and the message fields, not the domain's `chainId` or `name`/`version`, and
its transaction rules have no chain criterion. The signer pins the domain and chain itself before
sending a request, and cross-chain protection otherwise rests on the protocol contracts having
different addresses on each chain.

The policy cannot cover everything, so set up these yourself:

- **Export.** Anyone holding the API key and the Wallet Secret can export the account's raw
  private key (`POST …/export`) if the API key has the "Export (export private key)" scope. No
  policy covers export. Create the signer's API key **without** that scope.
- **Policy management.** Creating, updating, deleting or pausing a policy, and assigning one to
  an account, needs only the API key plus the "Manage (modify policies)" scope. Create the
  signer's API key **without** it; manage policies with a separate admin key kept off the agent's
  machine.
- **Key scopes.** The signer cannot check a key's scopes at boot. Add an IP allowlist to the API
  key as a second check.
- **Unnamed operations.** CDP allows by default any operation no rule names. Use the generated
  policy unchanged; do not trim the reject rules.
- **Project policy.** A project-level policy's decision is final and overrides the account
  policy. Boot checks this itself (see below): it lists every project policy and refuses to
  start if any rule's action is "accept". Keep the project policy empty or reject-only.
- **Smart-account upgrade.** CDP's EIP-7702 delegation endpoint, which upgrades the account to
  CDP's smart-account implementation, is not governed by policies either — another reason to keep
  the API key and the Wallet Secret on the agent's machine only. The generated policy rejects the
  user operations (`prepareUserOperation`, `sendUserOperation`) such a smart account would use.

Merchant REST tools are unavailable on CDP, same as Turnkey: `activate_merchant`, `add_product`,
`update_product`, `set_merchant_profile`, `get_merchant_stats`. They authenticate with a personal
signature over 32 raw bytes; CDP signs messages only as text, and raw bytes only through its
sign-hash endpoint, which no policy can restrict. Run merchant tools with `SIGNER_BACKEND=privy`,
`kms` or local.

At boot, the signer first lists every project-scoped policy (`GET /v2/policy-engine/policies
?scope=project`, paginating through `nextPageToken`) and refuses boot if any rule's action is
"accept", naming the policy id and the operation. A reject-only project policy, or none at all,
passes. This is what catches a narrowly permissive project policy — one that accepts something
outside the five probe shapes below, which the simulator alone would miss. A malformed response
(no `policies` array, or a `nextPageToken` that never terminates or repeats) also refuses boot
rather than silently passing. A 401 or 403 listing policies refuses with a permission-style
message (it never tells you to grant a scope); any other error — a transport failure, an
unexpected status, a response that doesn't decode — refuses boot with that error itself.

It then asks CDP's policy simulator (`POST /v2/policy-engine/simulate`, which signs nothing), once
per wallet, to run five probe requests: a raw hash (`signEvmHash`), a text message
(`signEvmMessage`), the self-test transaction as `signEvmTransaction` and again as a pre-built
`sendEvmTransaction`, and an ERC-2612 Permit as `signEvmTypedData`. Any answer other than "reject"
refuses boot — this catches a missing account policy, or a project policy that accepts any of
these probe requests. Together, boot checks: no accept rule in any project policy, and the five
probes.

Verified against a live CDP project (2026-10-29): uint fields are sent as decimal strings and CDP
compares them numerically; CDP accepts `EIP712Domain` in the policy's types; a policy denial is
HTTP 403 `policy_violation`; the policy simulator and the policy listing both work with a key that
has neither the Export nor the Manage scope.
