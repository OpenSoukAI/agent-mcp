package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// runPrivySetup is `opensouk-signer privy-setup`: with the OWNER's authorization key, create the
// policy, an Ethereum wallet owned by the owner quorum, and add the signer's key quorum as an
// additional signer bound to the policy. The owner key is used only here, never by the MCP
// server, so the signer that runs next to the agent cannot replace its own policy.
func runPrivySetup(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("privy-setup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ownerID := fs.String("owner-id", "", "key quorum id of the owner (keep its key off the agent's machine)")
	signerID := fs.String("signer-id", "", "key quorum id of the signer's authorization key (PRIVY_AUTHORIZATION_KEY)")
	policyPath := fs.String("policy", "", "policy file from `opensouk-signer policy --provider privy`")
	ownerEnv := fs.String("owner-key-env", "PRIVY_OWNER_AUTHORIZATION_KEY", "environment variable holding the owner's wallet-auth: key")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "opensouk-signer privy-setup: "+format+"\n", a...)
		return 1
	}
	if *ownerID == "" || *signerID == "" || *policyPath == "" {
		return fail("--owner-id, --signer-id and --policy are required")
	}
	if *ownerID == *signerID {
		return fail("the owner and the signer must be different key quorums: an owner can replace the wallet's policy")
	}
	raw, err := os.ReadFile(*policyPath)
	if err != nil {
		return fail("read policy: %v", err)
	}
	var policy map[string]any
	if err := json.Unmarshal(raw, &policy); err != nil {
		return fail("policy is not JSON: %v", err)
	}
	if strings.Contains(string(raw), "<") {
		return fail("the policy still has placeholders; generate it without --template")
	}
	cred, err := privyCredential(os.Getenv(*ownerEnv))
	if err != nil {
		return fail("%s: %v", *ownerEnv, strings.Replace(err.Error(), "PRIVY_AUTHORIZATION_KEY", *ownerEnv, 1))
	}
	appID, secret := strings.TrimSpace(os.Getenv("PRIVY_APP_ID")), strings.TrimSpace(os.Getenv("PRIVY_APP_SECRET"))
	if appID == "" || secret == "" {
		return fail("PRIVY_APP_ID and PRIVY_APP_SECRET are required")
	}
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("PRIVY_API_BASE_URL")), "/")
	if base == "" {
		base = privyDefaultBase
	}
	c := &privyClient{base: base, appID: appID, secret: secret, cred: cred, http: &http.Client{}}
	call := func(method, path string, body map[string]any) (map[string]any, error) {
		ctx, cancel := context.WithTimeout(ctx, providerCallTimeout)
		defer cancel()
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		return c.do(ctx, method, path, b)
	}

	policy["owner_id"] = *ownerID
	p, err := call(http.MethodPost, "/v1/policies", policy)
	if err != nil {
		return fail("create policy: %v", err)
	}
	policyID, _ := p["id"].(string)
	if policyID == "" {
		return fail("create policy returned no id")
	}
	w, err := call(http.MethodPost, "/v1/wallets", map[string]any{"chain_type": "ethereum", "owner_id": *ownerID, "policy_ids": []string{policyID}})
	if err != nil {
		return fail("create wallet (policy %s was created): %v", policyID, err)
	}
	walletID, _ := w["id"].(string)
	addr, _ := w["address"].(string)
	if !privyWalletID.MatchString(walletID) {
		return fail("create wallet returned id %q", walletID)
	}
	if _, err := call(http.MethodPatch, "/v1/wallets/"+walletID, map[string]any{
		"additional_signers": []any{map[string]any{"signer_id": *signerID, "override_policy_ids": []string{policyID}}},
	}); err != nil {
		return fail("add the signer to wallet %s (policy %s): %v", walletID, policyID, err)
	}
	// sign_agent_wallet_set refuses the '*' fallback, so name the agents the policy pins.
	entries := []string{"*:" + walletID}
	if ids := pinnedAgentIDs(policy); len(ids) > 0 {
		entries = entries[:0]
		for _, id := range ids {
			entries = append(entries, id+":"+walletID)
		}
	}
	fmt.Fprintf(stdout, "policy  %s\nwallet  %s\naddress %s\n\nAGENT_WALLETS=%s\n", policyID, walletID, addr, strings.Join(entries, ","))
	return 0
}

// pinnedAgentIDs are the agent ids a Privy policy allows AgentWalletSet for.
func pinnedAgentIDs(policy map[string]any) []string {
	var ids []string
	rules, _ := policy["rules"].([]any)
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		conds, _ := rule["conditions"].([]any)
		for _, c := range conds {
			cond, _ := c.(map[string]any)
			td, _ := cond["typed_data"].(map[string]any)
			if td["primary_type"] == specAgentWalletSet.primary && cond["field"] == "agentId" && cond["operator"] == "eq" {
				if id, ok := cond["value"].(string); ok {
					ids = append(ids, id)
				}
			}
		}
	}
	return ids
}
