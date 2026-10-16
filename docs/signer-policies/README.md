# Signer policies (Turnkey, Privy)

With `SIGNER_BACKEND=turnkey` or `privy`, the agent's key lives with the provider, and the
provider's policy decides what it signs. These files are that policy, version 1:

| File | Provider | Applied as |
|---|---|---|
| `turnkey.v1.json` | Turnkey | one policy per entry in `policies` |
| `privy.v1.json` | Privy | one policy, attached to the wallet |

Both allow exactly:

- the eight commitment types the signer tools sign, each only in its own EIP-712 domain, on the
  configured chain, with the protocol contract as `verifyingContract`;
- `ReceiveWithAuthorization` (ERC-3009) on USDC, only to the SplitRouter, and only up to the
  payment ceiling;
- transactions with no ETH value, each only to one function a signer tool calls on the
  ReviewRegistry, CommissionEscrow, MerchantRegistry or ProductRegistry (ten in all);
- on Privy, `personal_sign` of the binary hash the merchant REST tools authenticate with. Its
  EIP-191 prefix keeps it from producing a typed-data or transaction signature. Text, such as a
  sign-in message for another site, is denied: Privy evaluates message conditions only on valid
  UTF-8, so a DENY on any text leaves exactly the binary hash. Turnkey has no equivalent its
  policy can inspect, so those tools are unavailable there.

Everything else is denied. On Turnkey, raw payloads that are not EIP-712 are denied explicitly: a
raw hash can be any typed-data or transaction signature, so allowing one would void the rest.

## Make the policy for your chain

The committed files carry placeholders (`<CHAIN_ID>`, `<REVIEW_REGISTRY>`, `<USDC>`,
`<MAX_PAYMENT>`, `<TURNKEY_SIGNER_USER_ID>`, ...). Generate the real one with the signer's own
configuration, which resolves the contract addresses the same way the tools do:

```bash
CHAIN_ID=84532 BASE_RPC_URL=… referrer-signer policy --provider privy \
  --usdc 0x036CbD53842c5426634e7929541eC2318f3dCF7e --max-payment 5000000 > privy-policy.json

CHAIN_ID=84532 BASE_RPC_URL=… referrer-signer policy --provider turnkey \
  --usdc 0x036CbD53842c5426634e7929541eC2318f3dCF7e --max-payment 5000000 \
  --turnkey-user-id <signer user id> --wallet <wallet account address> > turnkey-policies.json
```

`--max-payment` defaults to `MAX_PAYMENT_PER_TX`. One of them is required.

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

## Changing a policy

Regenerate the templates after any change to a commitment type, its domain or the contracts:

```bash
go run ./cmd/signer policy --provider turnkey --template > docs/signer-policies/turnkey.v1.json
go run ./cmd/signer policy --provider privy --template > docs/signer-policies/privy.v1.json
```

`TestPolicyTemplatesAreGolden` fails until you do. A change that existing deployments must
re-apply is a new version: add `*.v2.json` and keep v1 until no wallet uses it.
