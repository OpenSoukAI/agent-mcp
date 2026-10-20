package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// fakePrivySetup records the setup calls and checks each carries the OWNER key's authorization
// signature (reusing fakePrivy's verifier with the owner's public key).
type setupCall struct {
	method, path string
	body         map[string]any
}

func newFakePrivySetup(t *testing.T) (*fakePrivy, string, *[]setupCall) {
	f, ownerKey := newFakePrivy(t)
	var calls []setupCall
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !f.authorised(r, body, true) {
			http.Error(w, `{"error":"invalid authorization signature"}`, http.StatusUnauthorized)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		calls = append(calls, setupCall{r.Method, r.URL.Path, m})
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/policies":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "pol1"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/wallets":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": f.id, "address": f.walletAddr().Hex(), "chain_type": "ethereum", "owner_id": m["owner_id"]})
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/wallets/"+f.id:
			_ = json.NewEncoder(w).Encode(map[string]any{"id": f.id})
		default:
			http.NotFound(w, r)
		}
	})
	return f, ownerKey, &calls
}

func TestPrivySetup(t *testing.T) {
	f, ownerKey, calls := newFakePrivySetup(t)
	policyFile := t.TempDir() + "/privy-policy.json"
	in := templatePolicyInputs()
	for k := range in.Addrs {
		in.Addrs[k] = "0x00000000000000000000000000000000000000a1"
	}
	in.ChainID, in.USDC, in.MaxValue, in.AgentIDs = "84532", "0x00000000000000000000000000000000000000b1", "5000000", []string{"12"}
	policy, _ := renderPolicy("privy", in)
	template, _ := renderPolicy("privy", templatePolicyInputs())
	templateFile := t.TempDir() + "/template.json"
	_ = os.WriteFile(templateFile, template, 0o600)
	if err := os.WriteFile(policyFile, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRIVY_API_BASE_URL", f.srv.URL)
	t.Setenv("PRIVY_APP_ID", f.appID)
	t.Setenv("PRIVY_APP_SECRET", f.secret)
	t.Setenv("PRIVY_OWNER_AUTHORIZATION_KEY", ownerKey)
	var out, errb bytes.Buffer
	code := runPrivySetup(context.Background(), []string{"--owner-id", "quorum-owner", "--signer-id", "quorum-signer", "--policy", policyFile}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if len(*calls) != 3 {
		t.Fatalf("calls %v, want create policy, create wallet, add signer", *calls)
	}
	c := *calls
	if c[0].path != "/v1/policies" || c[0].body["owner_id"] != "quorum-owner" || c[0].body["rules"] == nil {
		t.Fatalf("policy creation %v must carry the rules and the owner", c[0])
	}
	if c[1].path != "/v1/wallets" || c[1].body["owner_id"] != "quorum-owner" || c[1].body["chain_type"] != "ethereum" {
		t.Fatalf("wallet creation %v must set the owner", c[1])
	}
	signers, _ := c[2].body["additional_signers"].([]any)
	if c[2].method != http.MethodPatch || len(signers) != 1 {
		t.Fatalf("third call %v must PATCH one additional signer", c[2])
	}
	s := signers[0].(map[string]any)
	if s["signer_id"] != "quorum-signer" || !strings.Contains(strings.Join(anyStrings(s["override_policy_ids"]), ","), "pol1") {
		t.Fatalf("additional signer %v must be the signer key with the new policy", s)
	}
	o := out.String()
	if !strings.Contains(o, "AGENT_WALLETS=12:"+f.id+"\n") || !strings.Contains(o, f.walletAddr().Hex()) || strings.Contains(o, strings.TrimPrefix(ownerKey, "wallet-auth:")) {
		t.Fatalf("output %q must give the wallet id, its address and the AGENT_WALLETS line, and no key", o)
	}
	if code := runPrivySetup(context.Background(), []string{"--owner-id", "o", "--signer-id", "s", "--policy", templateFile}, &out, &errb); code == 0 {
		t.Fatal("a template with placeholders must be refused")
	}
	// The owner and signer must differ: a signer that owns the wallet can replace its policy.
	if code := runPrivySetup(context.Background(), []string{"--owner-id", "same", "--signer-id", "same", "--policy", policyFile}, &out, &errb); code == 0 {
		t.Fatal("an owner that is also the signer must be refused")
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
