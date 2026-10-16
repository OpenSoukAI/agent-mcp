package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func templatePath(provider string) string {
	return "../../docs/signer-policies/" + provider + ".v1.json"
}

func TestPolicyTemplatesAreGolden(t *testing.T) {
	for _, p := range []string{"turnkey", "privy"} {
		got, err := renderPolicy(p, templatePolicyInputs())
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(templatePath(p))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s template is stale (%v): regenerate with\n  go run ./cmd/signer policy --provider %s --template > docs/signer-policies/%s.v1.json", p, err, p, p)
		}
	}
}

func decodePolicy(t *testing.T, provider string, in policyInputs) map[string]any {
	t.Helper()
	b, err := renderPolicy(provider, in)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func privyRules(t *testing.T) []map[string]any {
	var out []map[string]any
	for _, r := range decodePolicy(t, "privy", templatePolicyInputs())["rules"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

// Privy evaluates a message condition only when the rule's types equal the request's exactly, so
// the policy's types must be the ones the tools actually send.
func TestPrivyPolicyTypesMatchBuilders(t *testing.T) {
	sent := map[string]any{}
	for _, spec := range allSpecs {
		td := sampleTypedData(spec)
		m, err := providerTypedDataJSON(td, "primary_type")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(m["types"])
		var types any
		_ = json.Unmarshal(b, &types)
		sent[spec.primary] = types
	}
	seen := 0
	for _, r := range privyRules(t) {
		for _, c := range r["conditions"].([]any) {
			cond := c.(map[string]any)
			if cond["field_source"] != "ethereum_typed_data_message" {
				continue
			}
			td := cond["typed_data"].(map[string]any)
			primary := td["primary_type"].(string)
			want, ok := sent[primary]
			if primary == erc3009ReceiveAuthorizationType {
				continue
			}
			if !ok || !reflect.DeepEqual(td["types"], want) {
				t.Fatalf("rule %v: types %v differ from what the tools send %v", r["name"], td["types"], want)
			}
			seen++
		}
	}
	if seen != len(allSpecs) {
		t.Fatalf("%d typed-data message conditions, want one per commitment type (%d)", seen, len(allSpecs))
	}
}

func TestPrivyPolicyHasNoWildcard(t *testing.T) {
	allowed := map[string]bool{"eth_signTypedData_v4": true, "eth_signTransaction": true, "personal_sign": true}
	for _, r := range privyRules(t) {
		if !allowed[r["method"].(string)] || r["action"] != "ALLOW" {
			t.Fatalf("rule %v: only ALLOW rules for %v belong in the policy; anything else is denied by default", r, allowed)
		}
	}
}

func turnkeyPolicies(t *testing.T) []map[string]any {
	var out []map[string]any
	for _, p := range decodePolicy(t, "turnkey", templatePolicyInputs())["policies"].([]any) {
		out = append(out, p.(map[string]any))
	}
	return out
}

func TestTurnkeyPolicyDeniesRawPayloads(t *testing.T) {
	denied := map[string]bool{}
	for _, p := range turnkeyPolicies(t) {
		cond, _ := p["condition"].(string)
		switch p["effect"] {
		case "EFFECT_DENY":
			for _, typ := range []string{"ACTIVITY_TYPE_SIGN_RAW_PAYLOAD", "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "ACTIVITY_TYPE_SIGN_RAW_PAYLOADS"} {
				if strings.Contains(cond, "activity.type == '"+typ+"'") && strings.Contains(cond, "activity.params.encoding != 'PAYLOAD_ENCODING_EIP712'") {
					denied[typ] = true
				}
			}
		case "EFFECT_ALLOW":
			if strings.TrimSpace(cond) == "" || !strings.Contains(p["consensus"].(string), "<TURNKEY_SIGNER_USER_ID>") {
				t.Fatalf("ALLOW policy %v must carry a condition and be scoped to the signer user", p["policyName"])
			}
		default:
			t.Fatalf("policy %v has effect %v", p["policyName"], p["effect"])
		}
	}
	if len(denied) != 3 {
		t.Fatalf("raw payloads denied for %v; all three raw-payload activity types must be", denied)
	}
}

func TestPoliciesCoverEveryPrimaryType(t *testing.T) {
	in := templatePolicyInputs()
	for _, provider := range []string{"turnkey", "privy"} {
		b, _ := renderPolicy(provider, in)
		s := string(b)
		for _, spec := range append(allSpecs, domainSpec{primary: erc3009ReceiveAuthorizationType}) {
			n := strings.Count(s, `'`+spec.primary+`'`)
			if provider == "privy" {
				n = 0
				for _, r := range privyRules(t) {
					if b, _ := json.Marshal(r); strings.Contains(string(b), `"primary_type":"`+spec.primary+`"`) {
						n++
					}
				}
			}
			if n != 1 {
				t.Fatalf("%s: %s is allowed by %d rules, want exactly one", provider, spec.primary, n)
			}
		}
		if strings.Contains(s, `\u00`) {
			t.Fatalf("%s policy is HTML-escaped; conditions must read as written", provider)
		}
		if strings.Contains(s, "TransferWithAuthorization") {
			t.Fatalf("%s policy names TransferWithAuthorization", provider)
		}
		for _, k := range []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry, keySplitRouter} {
			if !strings.Contains(s, in.Addrs[k]) {
				t.Fatalf("%s policy never names %s", provider, k)
			}
		}
		if !strings.Contains(s, in.MaxValue) || !strings.Contains(s, in.USDC) {
			t.Fatalf("%s policy must carry the USDC address and the payment ceiling", provider)
		}
	}
	// The transaction allowlist is exactly the four contracts the transaction tools call.
	for _, p := range turnkeyPolicies(t) {
		cond, _ := p["condition"].(string)
		if strings.Contains(cond, "ACTIVITY_TYPE_SIGN_TRANSACTION_V2") {
			for _, k := range []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry} {
				if !strings.Contains(cond, "eth.tx.to == '"+in.Addrs[k]+"'") {
					t.Fatalf("transaction policy misses %s: %s", k, cond)
				}
			}
			if strings.Contains(cond, in.Addrs[keySplitRouter]) {
				t.Fatal("no transaction tool calls the SplitRouter; it must not be in the transaction allowlist")
			}
		}
	}
}

func TestPolicyCLI(t *testing.T) {
	t.Setenv("CHAIN_ID", "84532")
	t.Setenv("MAX_PAYMENT_PER_TX", "")
	addrs := map[string]string{
		"REVIEW_REGISTRY_ADDRESS": "0x00000000000000000000000000000000000000A1", "COMMISSION_ESCROW_ADDRESS": "0x00000000000000000000000000000000000000A2",
		"MERCHANT_REGISTRY_ADDRESS": "0x00000000000000000000000000000000000000A3", "PRODUCT_REGISTRY_ADDRESS": "0x00000000000000000000000000000000000000A4",
		"SPLIT_ROUTER_ADDRESS": "0x00000000000000000000000000000000000000A5",
	}
	for k, v := range addrs {
		t.Setenv(k, v)
	}
	resetAddressCache()
	t.Cleanup(resetAddressCache)
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runPolicyCLI(context.Background(), args, &out, &errb)
		return code, out.String(), errb.String()
	}
	if code, _, e := run("--provider", "privy", "--usdc", "0x00000000000000000000000000000000000000B1"); code == 0 || !strings.Contains(e, "MAX_PAYMENT_PER_TX") {
		t.Fatalf("a policy without a payment ceiling must be refused, got %d %q", code, e)
	}
	if code, _, e := run("--provider", "turnkey", "--usdc", "0x00000000000000000000000000000000000000B1", "--max-payment", "5000000"); code == 0 || !strings.Contains(e, "turnkey-user-id") {
		t.Fatalf("a Turnkey policy without the signer user must be refused, got %d %q", code, e)
	}
	code, out, e := run("--provider", "privy", "--usdc", "0x00000000000000000000000000000000000000B1", "--max-payment", "5000000")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, e)
	}
	for _, v := range addrs {
		if !strings.Contains(out, strings.ToLower(v)) {
			t.Fatalf("output misses %s", v)
		}
	}
	if strings.Contains(out, "<") {
		t.Fatalf("a resolved policy still has placeholders: %s", out)
	}
	if code, _, e := run("--provider", "vault", "--template"); code == 0 || !strings.Contains(e, "provider") {
		t.Fatalf("unknown provider must be refused, got %d %q", code, e)
	}
}
