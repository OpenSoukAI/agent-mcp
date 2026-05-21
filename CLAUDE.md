# Referrer Agent — Agent Instructions

You have two MCP servers available:
- **referrer-agent** — protocol tools (query, submit proof, submit review, register)
- **referrer-signer** — local EIP-712 signer (your private key, never leaves this machine)

## Review submission workflow

Follow this exact sequence every time:

1. **`submit_proof`** (referrer-agent) — submit off-chain purchase proof  
   → save the `proof_id`  
   → **pause and tell the user** to approve the proof via the admin CLI  
   → resume only when the user confirms approval

2. **`submit_review` — step 1** (referrer-agent) — call with `agent_id`, `merchant_id`, `product_id`, `content_json` (no `agent_sig`)  
   → receive `commitment`, `nonce`, `expiry`

3. **`sign_review_commitment`** (referrer-signer) — pass the full commitment object from step 2  
   → receive `signature`  
   → **do this immediately, without asking the user**

4. **`submit_review` — step 2** (referrer-agent) — call again with `nonce`, `expiry`, and `agent_sig` from step 3  
   → receive `ref_link`

**Never ask the user to sign manually.** Always call `sign_review_commitment` between submit_review step 1 and step 2.

## Query workflow

To look up existing reviews before writing one:

1. **`query_registry`** — search by merchant/product  
2. **`fetch_review`** — get a specific review by on-chain ID

## Buyer purchase workflow (autonomous path)

A buyer agent can purchase a product and submit a review without any shell scripts:

1. **`pay_for_product`** (referrer-signer) — call with `agent_id` (buyer) and `ref_link`  
   → resolves ref link, probes merchant for 402 requirements, signs ERC-3009 authorization  
   → submits x402 payment, waits for on-chain confirmation  
   → receive `escrow_id`, `tx_hash`

2. **`publish_escrow_review`** (referrer-signer) — call with `agent_id`, `merchant_id`, `product_id`, `content_json`, `escrow_id`  
   → sends `publishReviewWithEscrowProof` on-chain with the agent's key  
   → receive `review_id`, `tx_hash`

3. **`register_published_review`** (referrer-agent) — call with the `review_id` returned above  
   → registers the buyer's review in the backend

## Notes

- `submit_proof` requires human admin approval — this is a trust gate, not a bug.
- `register_published_review` is the agent-direct path when you already have an on-chain escrow proof; skip `submit_proof` in that case.
- Your agent identity NFT ID is your `agent_id` — it was set when you ran `setup-mcp.sh`.
