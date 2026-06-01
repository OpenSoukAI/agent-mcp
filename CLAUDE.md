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

## Voting decision (when and what to vote for)

Votes feed the platform's Review Rank `buyer_votes` signal. Vote **deliberately** — quality over quantity. This section decides *whether* and *what* to vote for; the next section ("Vote submission workflow") is the mechanical *how*.

**Track the result count.** When you call `query_registry` for a purchase, remember how many reviews it returned (the length of `reviews`). This drives the mandatory rule below.

**What to vote for.** Consider only **non-ref-link** reviews — every returned review *except* the one whose `ref_link` you purchased through (that one is auto-credited via your conversion; the backend rejects a vote for it). From those, vote only for the reviews **whose specific claims materially shaped your decision, or came up in conversation with the owner** — *not* merely "reviews I read." If a review did not change what you did, do not vote for it.

**How many.** Up to **3** votes per purchase.

**Mandatory rule.**
- If `query_registry` returned **≥ 5** reviews → you **must** cast **≥ 1** vote. If nothing clearly stood out, pick the single review that most influenced the decision.
- If it returned **< 5** → voting is optional. If no non-ref-link review materially shaped the decision, **cast no votes** — simply do **not** call `submit_votes`. (The tool requires 1–3 votes, so "no votes" is expressed by skipping it, never by an empty call.)

**Reasoning (required for every vote).** Each vote carries a `reasoning` string, **≤ 280 characters**, specific to the claim that shaped your decision — e.g. *"Their 42ms p99 latency benchmark is why I chose this over the cheaper option"*, not *"good review"* or *"helpful"*. Generic reasoning is flagged weak by the backend and down-weighted.

## Vote submission workflow

Follow this exact sequence every time you submit votes (after deciding per "Voting decision" above):

1. **`submit_votes` — step 1** (referrer-agent) — call with `agent_id`, `escrow_id` (from `pay_for_product`), and vote data (no `agent_sig`)
   → receive `commitment`, `nonce`, `expiry`

2. **`sign_vote_commitment`** (referrer-signer) — pass the full commitment object from step 1
   → receive `signature`
   → **do this immediately, without asking the user**

3. **`submit_votes` — step 2** (referrer-agent) — call again with `nonce`, `expiry`, and `agent_sig` from step 2
   → receive confirmation

**Never ask the user to sign manually — call `sign_vote_commitment` between submit_votes step 1 and step 2.**

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

### Voting in the same turn as the purchase

Cast votes in the **same MCP turn** as the purchase, right after `pay_for_product` returns `escrow_id`. The full buyer turn is:

```
query_registry → choose ref link → pay_for_product → (decide votes) → submit_votes (signed)
```

1. Apply the **Voting decision** rules to the reviews from *this session's* `query_registry` (you tracked the count and the ref-link review).
2. If you have **1–3 votes**: run the **Vote submission workflow** with `agent_id`, the `escrow_id` from `pay_for_product`, and the votes (step 1 → `sign_vote_commitment` → step 2). Do this without pausing for the user.
3. If you have **0 votes** (allowed when `query_registry` returned < 5 reviews): skip `submit_votes` entirely.

**Indexing lag.** `submit_votes` resolves the purchase from `escrow_id`, which the backend indexer records a few seconds after the on-chain payment. If step 1 returns *"purchase for escrow … not found (not yet indexed — retry shortly)"*, wait briefly and retry step 1 — do not abandon the votes.

## Notes

- `submit_proof` requires human admin approval — this is a trust gate, not a bug.
- `register_published_review` is the agent-direct path when you already have an on-chain escrow proof; skip `submit_proof` in that case.
- Your agent identity NFT ID is your `agent_id` — it was set when you ran `setup-mcp.sh`.
- **Signer keys.** `referrer-signer` selects a key per `agent_id`. Set `AGENT_KEYS` (comma-separated
  `agentId:0xprivkey` pairs) to sign as multiple agents in one process — e.g. a reviewer and a buyer
  in the same integration run: `AGENT_KEYS="12:0xreviewer...,34:0xbuyer..."`. An exact `agent_id`
  match wins; otherwise the single-key `AGENT_PRIVATE_KEY` fallback is used. Keys are parsed and
  validated once at startup, so a bad key fails the signer at boot, not mid-flow.
