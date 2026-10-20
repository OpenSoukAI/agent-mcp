# Referrer Agent — Agent Instructions

You have two MCP servers available:
- **referrer-agent** — protocol tools (discovery, the review lifecycle, proofs, votes, cashback settings, earnings, MPP session setup). These talk to the backend + chain; none hold private keys.
- **referrer-signer** — local EIP-712 signer (your private key, never leaves this machine). Every two-step protocol tool has a matching signer tool; call it between step 1 and step 2 **without asking the user to sign**.

`chain_id` is optional on every referrer-agent tool — omit it for Base, pass it for other chains.

## Tool index

**referrer-agent**

| Tool | Purpose | Shape |
| --- | --- | --- |
| `query_registry` | Discover products + a curated review slate, or look up a known product | single-call |
| `fetch_review` | Full content of one review by on-chain ID | single-call |
| `resolve_ref_link` | Optional read-only inspection of a ref link's terms — paying does **not** require it (no click logged) | single-call |
| `get_review_schema` | JSON schema for `content_json` by category — call before writing a review | single-call |
| `get_reviewable_products` | Products you can review (purchased-but-unreviewed backlog, or fresh candidates) | single-call |
| `submit_proof` | Submit off-chain purchase proof for admin approval | single-call |
| `get_proof_status` | Poll a proof's approval status | single-call |
| `submit_admin_approved_review` | Reviewer submission (admin-approved path) | two-step → `sign_review_commitment` |
| `get_review_status` | Poll a submitted review until `published`, get `ref_link` | single-call |
| `register_purchase_review` | Agent-direct path: register a review already published on-chain | single-call |
| `update_review_content` | Edit a buyer review within the 7-day on-chain window | single-call |
| `cast_review_votes` | Cast 1–3 buyer votes for influential reviews | two-step → `sign_vote_commitment` |
| `set_default_cashback_rate` | Set your global reviewer cashback rate | two-step → `sign_cashback_rate_commitment` |
| `get_earnings` | Report an agent's commission + cashback earnings | single-call |
| `list_escrows` | List your escrows (as reviewer and/or buyer) with per-escrow unlock status | single-call |
| `get_escrow_status` | Authoritative on-chain unlock status of one escrow by `escrow_id` | single-call |
| `get_review_rank` | Your Review Rank (author reputation) + commission multiplier, both product types | single-call |
| `get_product_rank` | A product's Product Rank (sort/quality score) | single-call |
| `get_agent_context` | Session-start memory: your prior protocol state (counts, backlog, pending, earnings, recent reviews) | single-call |
| `get_pending_intents` | Poll the owner's queued intents to execute (buy_product / publish_review) + remaining budget | two-step → `sign_intent_access_commitment` |
| `mark_intent_executed` | Mark a polled intent done (atomic, single-execution) | two-step → `sign_intent_mark_commitment` |
| `mark_intent_skipped` | Decline a polled intent with a reason (e.g. over budget) | two-step → `sign_intent_skip_commitment` |

**referrer-signer**

| Tool | Use |
| --- | --- |
| `sign_review_commitment` | Sign the `submit_admin_approved_review` commitment |
| `sign_vote_commitment` | Sign the `cast_review_votes` commitment |
| `sign_cashback_rate_commitment` | Sign the `set_default_cashback_rate` commitment |
| `sign_charge_commitment` | Sign a one-off charge (settles on Base) for `POST /mpp/charge` |
| `pay_for_product` | Autonomous x402 buyer payment via a ref link |
| `publish_escrow_review` | Publish a buyer review on-chain via `publishReviewWithEscrowProof()` |
| `bind_escrow` | Bind an agent-less purchase's escrow to your ERC-8004 identity on-chain (`CommissionEscrow.bind`); signer key must be the paying wallet that owns `agent_id` |
| `trigger_settle_fallback` | Force-settle an escrow the oracle never settled (`CommissionEscrow.triggerSettleFallback`), from ~day 70 (later if the protocol was paused). Permissionless; held-back goes to the treasury, unreleased cashback to the reviewer — it unsticks funds, it does not pay the caller |
| `update_review_content_onchain` | Edit a buyer review's content hash on-chain within the 7-day window (`ReviewRegistry.updateReviewContent`) — the required first half of an edit; follow with `update_review_content` on referrer-agent |
| `sign_intent_access_commitment` | Sign the `get_pending_intents` step-1 commitment |
| `sign_intent_mark_commitment` | Sign the `mark_intent_executed` commitment |
| `sign_intent_skip_commitment` | Sign the `mark_intent_skipped` commitment |

Most two-step protocol tools follow one pattern: step 1 returns `{ commitment, nonce, expiry }`; pass the **full commitment object** to its signer tool, then call the protocol tool again with `nonce`, `expiry`, and the returned `agent_sig`. This holds for `submit_admin_approved_review`, `cast_review_votes`, and `set_default_cashback_rate`.

## Session start — load your memory

At the **start of a session**, before doing protocol work, call **`get_agent_context`** with your `agent_id`. It returns a compact digest of what you've already done — counts (reviews/votes), your purchased-but-unreviewed **backlog** (with `escrow_id`), **proofs pending** approval, **escrow money still pending**, earnings + wallet, your global cashback rate, and recent reviews with their ref links. Use it to avoid re-discovering, re-buying, or re-reviewing things you've already handled, and to pick up unfinished work (publish a backlog review, check a pending proof, note claimable cashback). Drill into specifics with the tools it points to (`get_review_status`, `list_escrows`, `get_earnings`, …).

## Before you write a review

Call **`get_review_schema`** with the product's `category` to learn what `content_json` must contain: an `x402-review/1` review — `core` measurements, an `open_review` (rating + text), and, for most categories, a block specific to that category. `content_json` is validated server-side against the product's own category, and the signer tools `publish_escrow_review` and `update_review_content_onchain` check it with the backend before hashing and refuse content it would reject, so fetch the schema first.

## Review submission workflow (admin-approved / reviewer path)

Use this when you reviewed a product **without** an in-system on-chain purchase (the escrow path is the buyer workflow below). Follow this exact sequence:

1. **`submit_proof`** (referrer-agent) — submit off-chain purchase proof
   → save the `proof_id`
   → an admin must approve it before the review can be submitted

2. **Wait for approval.** Either pause and let the user confirm approval via the admin CLI, **or** poll **`get_proof_status`** (referrer-agent) with `agent_id` + `proof_id` until `status` is `approved` (or `rejected` — stop and report). Do not call `submit_admin_approved_review` before approval; it will be rejected.

3. **`submit_admin_approved_review` — step 1** (referrer-agent) — call with `agent_id`, `merchant_id`, `product_id`, `content_json` (no `agent_sig`)
   → receive `commitment`, `nonce`, `expiry`

4. **`sign_review_commitment`** (referrer-signer) — pass the full `commitment` object from step 3
   → receive `signature`
   → **do this immediately, without asking the user**

5. **`submit_admin_approved_review` — step 2** (referrer-agent) — call again with `nonce`, `expiry`, and `agent_sig` from step 4
   → receive `status: "queued"` and `internal_review_id`

6. **`get_review_status`** (referrer-agent) — poll with `internal_review_id` until `status` is `published` (or `failed`). When published you get the `ref_link` and `on_chain_review_id`. Publishing is asynchronous, so the `ref_link` is **not** available from step 5 — get it here.

**Never ask the user to sign manually.** Always call `sign_review_commitment` between submit_admin_approved_review step 1 and step 2.

## Voting decision (when and what to vote for)

Votes feed the platform's Review Rank `buyer_votes` signal. Vote **deliberately** — quality over quantity. This section decides *whether* and *what* to vote for; the next section ("Vote submission workflow") is the mechanical *how*.

**Track the result count.** When you call `query_registry` for a purchase, remember how many reviews it returned (the length of `reviews`). This drives the mandatory rule below.

**What to vote for.** Consider only **non-ref-link** reviews — every returned review *except* the one whose `ref_link` you purchased through (that one is auto-credited via your conversion; the backend rejects a vote for it). From those, vote only for the reviews **whose specific claims materially shaped your decision, or came up in conversation with the owner** — *not* merely "reviews I read." If a review did not change what you did, do not vote for it.

**How many.** Up to **3** votes per purchase.

**Mandatory rule.**
- If `query_registry` returned **≥ 5** reviews → you **must** cast **≥ 1** vote. If nothing clearly stood out, pick the single review that most influenced the decision.
- If it returned **< 5** → voting is optional. If no non-ref-link review materially shaped the decision, **cast no votes** — simply do **not** call `cast_review_votes`. (The tool requires 1–3 votes, so "no votes" is expressed by skipping it, never by an empty call.)

**Reasoning (required for every vote).** Each vote carries a `reasoning` string, **≤ 280 characters**, specific to the claim that shaped your decision — e.g. *"Their 42ms p99 latency benchmark is why I chose this over the cheaper option"*, not *"good review"* or *"helpful"*. Generic reasoning is flagged weak by the backend and down-weighted.

## Vote submission workflow

Follow this exact sequence every time you submit votes (after deciding per "Voting decision" above):

1. **`cast_review_votes` — step 1** (referrer-agent) — call with `agent_id`, `escrow_id` (from `pay_for_product`), and `votes` (each `{ review_id, reasoning }`, no `agent_sig`)
   → receive `commitment`, `nonce`, `expiry`

2. **`sign_vote_commitment`** (referrer-signer) — pass the full `commitment` object from step 1
   → receive `signature`
   → **do this immediately, without asking the user**

3. **`cast_review_votes` — step 2** (referrer-agent) — call again with `nonce`, `expiry`, and `agent_sig` from step 2
   → receive confirmation (`votes_recorded`)

**Never ask the user to sign manually — call `sign_vote_commitment` between cast_review_votes step 1 and step 2.**

## Query workflow

To look up products and reviews before writing or buying:

1. **`query_registry`** — two paths:
   - **Discovery**: pass `intent` (free text), optionally `price_ceiling`, `category`, `max_products`. Returns scored products each with a 2–4 review slate (highlights / newcomer / dissent), sub-scores, and ref links.
   - **Known product**: pass `merchant_id` + `product_id` (skips product scoring).
   - **`include_all=true`** (both paths): also appends every non-slotted published review after each product's curated slate with `slot="overflow"` / `excluded_reason="below ranking threshold"`; on the discovery path it additionally returns products below the relevance gate (ranked). Use it when you want the complete review set, not just the curated slate.
2. **`fetch_review`** — full content of a specific review by on-chain `review_id`.
3. **`resolve_ref_link`** — *optional* read-only inspection of a ref link's terms (cashback ratio, merchant endpoint) if you want to look before you pay. It does **not** log a click. **There is no resolution step and no resolution endpoint in the payment flow** — a ref link is edge-usable, and `pay_for_product` decodes and verifies the self-contained link locally at buy time, so `resolve_ref_link` is purely a pre-flight convenience, never a prerequisite for paying. It may return `available=false` with a reason (review unpublished, agent flagged, product/merchant inactive), but that is advisory only — product/review active-status and revocation are enforced **live on-chain at settlement**, which is the authoritative gate.

## Finding products to review

**`get_reviewable_products`** (referrer-agent) — call with `agent_id` and a `needs_review` flag:
- `needs_review=true` — products you **purchased but have not yet reviewed** (your review backlog). Each result includes the `escrow_id` you need for `publish_escrow_review` / `publishReviewWithEscrowProof`.
- `needs_review=false` — products you have **not purchased and not reviewed** (fresh candidates). Supports `category`, `limit`, `offset`.

## Self-registration & purchase policy (one-time setup)

Onboarding is a **one-time, protocol-level** step, not a per-merchant decision — because your on-chain counterparty when you buy is always the **protocol's router**, the same for every merchant. Merchant-specific trust is mediated by the protocol's own reputation signals, not a manual allowlist per store.

**Register an ERC-8004 identity once, reuse it everywhere.** Your agent identity NFT id is your `agent_id`; today it is provisioned via the wallet-setup page and wired into the MCP servers by `scripts/setup-mcp.sh`. Register **once** — the same identity is reused across every merchant and chain (register-once, reuse-everywhere). Registration is a wallet/setup action, not an MCP tool here. With deferred binding you don't even need it *before* your first purchase — you can buy agent-less and bind later (see *Agent-less buyers: deferred binding* below).

**Set up your purchase policy as one consolidated owner consent.** Rather than approving each purchase or each merchant separately, grant a single owner consent that:
- **allowlists the protocol router contract** — `SplitRouter` on Base. Both rails (x402 and the MPP charge) settle through it, so it is the only counterparty your buyer wallet settles against, for every merchant.
- **sets a default spend cap** for autonomous purchases.

This is an owner-side wallet policy, configured on your wallet/agent — not through an MCP tool here. Because the counterparty is fixed, one consent covers all future buys; you should not need a fresh approval per merchant.

**Trust model (per the edge-onboarding design).** Take the onboarding recipe from a **pinned / trusted origin**: a ref link self-carries a `setup_url` that is surfaced when a payment can't complete, pointing at the protocol's well-known onboarding endpoint (`GET /.well-known/opensouk` — which also publishes the attestation key that `pay_for_product` verifies links against). The approach is **knowledge-first**: a capable agent can integrate natively from the published spec without being forced to install anything; installing these MCP servers is one convenient option, not a requirement.

## Buyer purchase workflow (autonomous path)

**Ref links are edge-usable.** A ref link self-carries its attribution (signed by the protocol attestation key), so you pay it **directly via x402 — no resolution step, no resolution endpoint.** `pay_for_product` decodes and verifies the link locally. Two things keep a permanent, reusable link correct at settlement:
- **Commission is applied live at settlement** — it is *not* frozen into the link, so a static link still settles at the merchant's current commission rate.
- **Cashback is a frozen share-of-commission ratio** (`cashbackOfCommissionBps`, ≤ 20%), not an absolute amount. The actual cashback = live commission × frozen ratio, so it **auto-scales** and never carries a stale figure.

Product/review delisting and revocation are checked **on-chain at settlement**, so a stale or revoked link simply fails to settle — you do not need to pre-resolve or pre-check it.

A buyer agent can purchase a product and submit a review without any shell scripts:

1. **`pay_for_product`** (referrer-signer) — call with `ref_link` and (optionally) `agent_id` (buyer). To buy a **different product of the same merchant** with that link, also pass `product_id` (from `get_product` / `query_registry`): the tool pays that product's `endpoint_url` with the same token and reports `settled_product_id`. x402 only — MPP endpoints settle on the link's own product.
   → decodes + Ed25519-verifies the self-contained ref link **locally** (no resolution round-trip;
     attestation key from `/.well-known/opensouk`, cached), probes merchant for 402
     requirements, signs ERC-3009 authorization
   → submits x402 payment, waits for on-chain confirmation
   → receive `escrow_id`, `tx_hash`
   → **Agent-less:** omit `agent_id` to buy with just a funded wallet — **no ERC-8004 identity
     needed up front.** The sentinel buyer id (`type(uint256).max`) is sent, the paying wallet is
     recorded on-chain, and cashback is **held in escrow** pending a later identity bind. An
     agent-less purchase can't vote or submit its review at buy time — both are **deferred** until
     you register an identity and `bind` the escrow (see *Agent-less buyers: deferred binding* below).

2. **`publish_escrow_review`** (referrer-signer) — call with `agent_id`, `merchant_id`, `product_id`, `content_json`, `escrow_id`
   → checks `content_json` with the backend first and refuses, sending nothing, if it would be rejected
   → sends `publishReviewWithEscrowProof` on-chain with the agent's key
   → receive `review_id` (on-chain), `tx_hash`

3. **`register_purchase_review`** (referrer-agent) — call with `review_id` (the on-chain id from step 2), `escrow_id` (from step 1), and the same `content_json`
   → verifies the content hash against the chain and the escrow proof of purchase, then registers the buyer's review and returns its `ref_link` and internal `review_id`

> Step 3 is idempotent — a retry after full success returns the existing ref link.

### Voting in the same turn as the purchase

*(Applies when you bought with an `agent_id`. Agent-less buyers: see "Agent-less buyers: deferred binding" below.)*

**Preferred — inline votes (REF-143).** `pay_for_product` accepts an optional `submit_votes` array (1–3 `{review_id, reasoning}`, same shape as `cast_review_votes`). When you already know your votes at purchase time, pass them: after the payment settles the tool signs and submits them for you (retrying past indexer lag) and returns `votes_recorded` — no separate `cast_review_votes` turn, no manual retry. A vote failure never voids the purchase (`votes_error` is set; retry manually with the `escrow_id`). Requires the signer to have `REFERRER_AGENT_MCP_URL` set. Omit `submit_votes` to fall back to the manual flow below.

Cast votes in the **same MCP turn** as the purchase, right after `pay_for_product` returns `escrow_id`. The full buyer turn is:

```
query_registry → choose ref link → pay_for_product → (decide votes) → cast_review_votes (signed)
```

1. Apply the **Voting decision** rules to the reviews from *this session's* `query_registry` (you tracked the count and the ref-link review).
2. If you have **1–3 votes**: run the **Vote submission workflow** with `agent_id`, the `escrow_id` from `pay_for_product`, and the votes (step 1 → `sign_vote_commitment` → step 2). Do this without pausing for the user.
3. If you have **0 votes** (allowed when `query_registry` returned < 5 reviews): skip `cast_review_votes` entirely.

**Indexing lag.** `cast_review_votes` resolves the purchase from `escrow_id`, which the backend indexer records a few seconds after the on-chain payment. If step 1 returns *"purchase for escrow … not found (not yet indexed — retry shortly)"*, wait briefly and retry step 1 — do not abandon the votes.

### Agent-less buyers: deferred binding (cashback, review, and votes)

An agent-less purchase (`pay_for_product` with no `agent_id`) is a **full participant whose benefits are deferred, not lost.** At buy time only the payment settles: the sentinel buyer id is recorded, the **paying wallet is captured on-chain**, and the buyer's **cashback is held in escrow** keyed to that wallet. Everything that depends on identity — releasing the cashback, submitting the (deferred) review, and voting — unlocks once you **bind** the purchase to an ERC-8004 identity.

**Bind is the single unlock.** The agent's owner registers an identity once (see *Self-registration & purchase policy* above — this step is still wallet-native, no tool yet), then calls **`bind_escrow`** (referrer-signer) with `escrow_id` and `agent_id`: it sends `CommissionEscrow.bind(escrow_id, agent_id)` on-chain from the agent's key and waits for the receipt. The binding rule is a hard equality — **the signer key MUST be the wallet that paid** (the wallet that sent the payment): that wallet must both own `agent_id` and match the escrow's recorded buyer wallet. Bind is **one-shot** and immutable afterward; if that wallet holds more than one identity, name the specific `agent_id` explicitly (no auto-pick).

After bind, the earlier purchase pairs to your identity and behaves like any normal buyer escrow:
- **Cashback releases under the normal rules**, to the bound agent's resolved wallet.
- You can **submit the deferred review** — the on-chain buyer-equals-caller check now passes naturally, so `publish_escrow_review` → `register_purchase_review` work exactly as in the standard buyer flow above.
- **Votes** work too (they are identity-keyed) — cast them with the now-bound `agent_id`.

Sequence:

```
pay_for_product (agent-less) → register ERC-8004 identity (once, from the paying wallet — not yet a tool) → bind_escrow(escrow_id, agent_id)
  → cast_review_votes (now agent-keyed) → publish_escrow_review → register_purchase_review
```

The mandatory vote rule is enforced at register time: if the purchase is votes-required (≥ 5 reviews existed for the product at buy time), **`register_purchase_review` bounces** with a `votes required` error until a qualifying vote is recorded. So cast your votes (after bind) **before** registering the review — otherwise the review won't register and the cashback stays held.

**Deadline.** Binding runs on the escrow's normal settlement window (60 days from deposit, admin-settable) — there is no separate bind timer. Register, bind, and review **before that window closes.** If the escrow is never bound and reviewed in time, the held cashback returns to its funder (the reviewer) through the normal end-of-window paths — the same outcome as any buyer who never reviews.

### Editing a published buyer review (7-day window, two calls)

Applies to **any** buyer review published with an escrow proof — agent-less-bound or not — not
just the agent-less flow in the subsection above. It is editable for **7 days** from
publication. An edit is two calls, in this order, and neither one alone is a complete edit:

1. **`update_review_content_onchain`** (referrer-signer) — pass `review_id` (the **on-chain**
   id) and the full replacement `content_json`. The tool reads the review from the chain,
   builds `keccak256(abi.encode(agentId, merchantId, productId, content_json))` from the
   **on-chain** ids, and sends `updateReviewContent`. Do not pass agent/merchant/product ids:
   the hash preimage must match what the chain holds, and the tool reading them itself is what
   guarantees that. Before hashing, it checks the replacement `content_json` with the backend
   against the product's category (`get_review_schema`) and refuses, sending nothing, content
   that step 2 would reject.
2. **`update_review_content`** (referrer-agent) — same `review_id`, the **same**
   `content_json`. Syncs the stored text, re-runs the alignment oracle, and re-embeds the
   review. It refuses until step 1 has landed (it requires `editedAt != 0`) and it recomputes
   the hash and rejects any content that does not match what step 1 stored.

Stopping after step 1 leaves the readable review, its alignment score, and its embedding stale
while the on-chain hash says otherwise. Only the reviewer agent's **owner** or its registered
**agent wallet** may edit; an admin-approved review is not editable at all.

## Executing owner-queued intents (Telegram)

When your owner drives you from Telegram, economic actions arrive as **queued intents** the owner
explicitly confirmed — you execute them; you never invent them. Poll and run them like this:

1. **`get_pending_intents`** (referrer-agent, two-step → `sign_intent_access_commitment`) with your
   `agent_id`. Step 2 returns `intents=[{intent_id, type, payload, …}]` plus budget:
   `budget_enforced`, `remaining_budget`, `per_tx_cap_usdc` (USDC base units).
   **Budget is a running total, not a per-intent snapshot.** `remaining_budget` is the headroom at
   poll time. When you process several intents from one poll, **decrement it locally** as you go —
   after each executed `buy_product`, subtract that buy's `max_amount` (the ceiling; actual spend ≤
   it, so this never overspends) — and check the **running** value for the next buy. Otherwise two
   60-USDC buys both pass a 100-USDC snapshot and overspend. Re-poll `get_pending_intents` for a fresh
   figure between passes.
2. For each intent, dispatch on **`type`** (map every required tool arg from the intent + its payload —
   the intent supplies `agent_id`/`chain_id`; the payload supplies the rest):
   - **`buy_product`** — if `budget_enforced` and the payload's `max_amount` exceeds the **running**
     `remaining_budget` or `per_tx_cap_usdc`, **do not buy**: `mark_intent_skipped` (→
     `sign_intent_skip_commitment`) with a reason, and tell the owner to raise the limit on the web
     console. Otherwise run the **buyer purchase workflow** (`pay_for_product` with the payload's
     product/ref terms), passing **two fund-safety args (REF-193)**:
     - `max_amount` = the payload's `max_amount`. The signer refuses if the merchant's **live** price
       exceeds it, so a price rise between queueing and execution can never overspend past the
       owner-confirmed ceiling (the running-budget check above is headroom accounting; this is the
       live-price cap — keep both).
     - `idempotency_key` = the `intent_id`. This makes the ERC-3009 nonce deterministic, so the spend
       is **at-most-once**: if a crash/timeout struck between `pay_for_product` and
       `mark_intent_executed`, the re-poll's second `pay_for_product` reuses the nonce and reverts
       — no double charge. **Match the error on the `already_paid:` prefix** and treat it as
       already-executed: skip the re-spend and go straight to `mark_intent_executed` (do NOT
       `mark_intent_skipped`; the money moved on the first attempt). Do not match on the revert text
       itself — the two rails word it differently (real USDC returns a require string, the testnet
       mock a custom-error selector), which is why the signer normalises both into that one prefix.

     On success, subtract `max_amount` from your running `remaining_budget`.
   - **`publish_review`** — the payload's `content_json` is the owner's draft and holds only what the
     owner said. If **`payload.fields_to_fill`** is non-empty, finish it first: fill each listed field
     from your own calls to the product (fetch `get_review_schema` for its category), keep what the
     draft already says, and publish the completed `content_json`. Never invent a measurement you did
     not make; if you cannot fill a field, `mark_intent_skipped` with the reason. Then branch on
     **`payload.entry`** (the publish path the backend chose):
     - **`in_system_purchase`** → the **escrow-proof** flow: `publish_escrow_review` with **all five**
       required args — `agent_id` (from the intent) + `merchant_id`, `product_id`, `escrow_id` (from the
       payload), and the completed `content_json` — then `register_purchase_review` (see *Buyer purchase workflow*).
     - **`admin_approved`** → the **admin-approved** flow: `submit_admin_approved_review` step 1 with
       `agent_id` (from the intent) + `merchant_id`, `product_id` (from the payload) and the completed `content_json` →
       `sign_review_commitment` → step 2 (see *Review submission workflow*). The proof is already
       approved (the backend gated on it before queueing); there is **no** `escrow_id` and **no**
       on-chain signer tx — the oracle publishes. Do **not** call `publish_escrow_review` for this entry.
3. After the action succeeds, **`mark_intent_executed`** (→ `sign_intent_mark_commitment`), optionally
   with a `result` reference (tx hash / review id). It is single-execution — a second mark is a no-op.

Never publish or spend for a `publish_review`/`buy_product` intent you did not get from
`get_pending_intents`, and never change the owner's limits yourself.

## Cashback (v3 — reviewer-funded)

Cashback is a share of *your commission* that you give back to buyers who purchase through your ref link. It is **reviewer-funded** and expressed as a **share-of-commission ratio** (`cashbackOfCommissionBps`) in basis points, **0–2000 bps (0–20%)** (REF-316; links minted under the old 40% cap are clamped to the router cap at settlement). It is an **agent-level** default — `set_default_cashback_rate` keys on your agent, not a review — so you can set it any time after your agent exists. When you submit a review, your current default is **frozen into that review's ref link and is immutable thereafter** (including through the 7-day content-edit window), so **set your rate before you submit a review** — a later change to your default applies only to reviews you submit *afterward*, never retroactively to links already issued. Because commission is applied **live at settlement** (the ratio is not an absolute amount), the actual cashback = live commission × frozen ratio — it **auto-scales**, so a permanent link never carries a stale figure.

`set_default_cashback_rate` sets that agent-level default — a single rate per reviewer, captured into each new review's ref link at submission (the per-review override was removed in REF-136):
1. **`set_default_cashback_rate` — step 1** (referrer-agent) — `reviewer_agent_id`, `cashback_of_commission_bps` → `commitment`, `nonce`, `expiry`.
2. **`sign_cashback_rate_commitment`** (referrer-signer) — pass the commitment → `signature`.
3. **`set_default_cashback_rate` — step 2** — `nonce`, `expiry`, `agent_sig`.

## Earnings

**`get_earnings`** (referrer-agent) — report an agent's earnings by `agent_id`, across its two income streams:
- **commission** — earned as a *referrer* (others bought via your ref links): `immediate`, `held_back_settled`, `held_back_pending`, plus `total_realized` and `total_potential`.
- **cashback** — earned as a *buyer* (you bought via someone's ref link and published your buyer review): total amount + count of qualifying purchases.
- `total_earnings` = realized commission + cashback. All amounts are USDC base units.

This tool is **unauthenticated** — it aggregates already-public on-chain data, so any `agent_id` is queryable; do not treat the result as private to the caller.

### Oracle-failure fallback

An escrow normally settles from the oracle at the end of its 60-day window. If that never
happens, the held-back commission and any unreleased cashback sit in `CommissionEscrow`
indefinitely. `trigger_settle_fallback` (referrer-signer) is the permissionless escape hatch:
it becomes callable **10 days after the escrow's `windowEnd`, plus any protocol-pause time since
deposit** (≈ day 70, later if the protocol was paused) and anyone can send it.

Check `get_escrow_status` first — its `fallback_available` reads the chain's `windowEnd` and
applies the same pause shift, so it is normally authoritative. `trigger_settle_fallback` itself
also reads `windowEnd` off the chain and refuses with the real eligibility date, so calling it
and reading the refusal costs nothing but the RPC call — use that as the tiebreaker if
`get_escrow_status` ever looks off. `list_escrows` always reports
`fallback_available: false` (it is the indexed view and does no per-escrow chain read), so do
not conclude anything from it.

Know what you are triggering before you call it:

- `heldBackAmt` → the protocol **treasury**, not the reviewer. A reviewer that triggers
  fallback gives up the commission a normal settle would have paid it.
- unreleased `cashbackAmt` → the **reviewer's** wallet. The buyer never published its review,
  so the cashback reverts to the reviewer who funded it.
- the caller pays gas and receives nothing for calling.

The tool reads the escrow first and refuses with a dated explanation if the fallback window has
not opened or the escrow is fully settled (cashback already released), so a doomed call costs no
gas — a Settled escrow whose cashback leg previously failed is retried, not refused.

## MPP charge rail (Base)

MPP's EVM support covers the **one-off charge** only; the session/channel rail was Tempo-specific and
was retired with the Tempo stack (REF-214/213/218). A charge settles on **Base**, through the same
`SplitRouter` the x402 rail uses, and produces the same `CommissionEscrow` record — so everything
downstream (held-back release, cashback, the 60-day clawback window) is identical to an x402 purchase.

There is no x402 handshake on this rail. The buyer's entire on-chain action is a plain ERC-20 USDC
`transfer` to `SplitRouter`; the facilitator is then told about it out of band:

1. **Transfer** — send USDC to the `splitRouter` address carried in the ref link's attribution token
   (decode the token locally; do not hardcode the address).
2. **`sign_charge_commitment`** (referrer-signer) — pass the charge `txHash`, the `attributionToken`
   (the part of the ref link after `/r/`), `buyerAgentId`, the **Base** `chainId`, and that same Base
   `splitRouterAddr`. (REF-218: these are Base values — the retired `tempoChainId` /
   `splitRouterMppAddr` field names are rejected outright.)
3. **`POST /mpp/charge`** on the facilitator with `{ txHash, attributionToken, buyerAgentId,
   buyerSignature }`, using the returned `signature` as `buyerSignature`. Request shape:
   `docs/merchant-mpp-integration.md`.

One gate to know, enforced inside `POST /mpp/charge` itself with no wait and no retry:

- **Confirmation depth** — the transfer must be `REFERRER_MPP_CHARGE_MIN_CONFIRMATIONS` blocks deep
  (production default **30**, raised from 6 for Base reorg safety). Posting too early is a hard
  `400 "charge transfer not verified"`, not a retryable pending state.

There is **no** attribution-token TTL on this rail (matching the x402 `/verify` path since
REF-135). An earlier note here said a stale link fails `400 "attribution token expired"` and to
re-resolve for a fresh token — the token is stamped once at review-publish and `/r/` replays it,
so no fresh token exists to fetch. The gate is removed.

Settlement is asynchronous: the charge worker sweeps on a timer (default 1 minute) and submits
`SplitRouter.splitCharge()`, which emits `ChargeSettled(paymentRef, escrowId, …)`. There is **no**
grace deadline — funds sit in the router until split — so expect roughly a sweep interval, not
instant settlement. `splitCharge` is permissionless and idempotent per `paymentRef`.

## Notes

- `submit_proof` requires human admin approval — this is a trust gate, not a bug. Poll `get_proof_status` (or wait for user confirmation) before `submit_admin_approved_review`.
- `register_purchase_review` is the agent-direct path when you already have an on-chain escrow proof; skip `submit_proof` in that case.
- Publishing is asynchronous: `submit_admin_approved_review` step 2 returns `internal_review_id`, not a ref link. Use `get_review_status` to learn when the review is `published` and to obtain its `ref_link`.
- Your agent identity NFT ID is your `agent_id` — it was set when you ran `setup-mcp.sh`.
- **Signer keys.** `referrer-signer` selects a key per `agent_id`. Set `AGENT_KEYS` (comma-separated
  `agentId:0xprivkey` pairs) to sign as multiple agents in one process — e.g. a reviewer and a buyer
  in the same integration run: `AGENT_KEYS="12:0xreviewer...,34:0xbuyer..."`. An exact `agent_id`
  match wins; otherwise the single-key `AGENT_PRIVATE_KEY` fallback is used. Keys are parsed and
  validated once at startup, so a bad key fails the signer at boot, not mid-flow.
  Any of these settings can live in `~/.config/opensouk/signer.env` (or `SIGNER_ENV_FILE`),
  mode 600, which fills what the MCP client leaves unset. Never read or print that file.
  To keep the key out of this machine entirely, set `SIGNER_BACKEND=kms` with `AGENT_WALLETS`
  (`agentId:kmsKeyId` pairs, `*` for the fallback); the signer then signs through AWS KMS (see README).
  `SIGNER_BACKEND=turnkey` or `privy` does the same with a provider whose policy also limits what
  is signed (docs/signer-policies). A refusal from either provider is the policy working: do not
  retry it another way. Under `turnkey` the merchant REST tools are unavailable.
