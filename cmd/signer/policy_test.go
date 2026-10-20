package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func templatePath(provider string) string {
	return "../../docs/signer-policies/" + provider + "." + policyVersion + ".json"
}

func TestPolicyTemplatesAreGolden(t *testing.T) {
	for _, p := range []string{"turnkey", "privy"} {
		got, err := renderPolicy(p, templatePolicyInputs())
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(templatePath(p))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s template is stale (%v): regenerate with\n  go run ./cmd/signer policy --provider %s --template > docs/signer-policies/%s.%s.json", p, err, p, p, policyVersion)
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
		m, err := providerTypedDataJSON(td, "primary_type", false)
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
	denies := 0
	for _, r := range privyRules(t) {
		if !allowed[r["method"].(string)] {
			t.Fatalf("rule %v: only %v belong in the policy; anything else is denied by default", r, allowed)
		}
		if r["action"] == "DENY" {
			denies++
			// The one DENY refuses personal_sign of any text (a message condition evaluates only on
			// valid UTF-8), leaving the binary agent-auth hash. Live 2026-10-16: 8/8 hashes signed,
			// a sign-in message was refused.
			b, _ := json.Marshal(r)
			if r["method"] != "personal_sign" || !strings.Contains(string(b), `"field":"byte_length","field_source":"message","operator":"gte","value":"0"`) {
				t.Fatalf("unexpected DENY rule %s", b)
			}
		} else if r["action"] != "ALLOW" {
			t.Fatalf("rule %v has action %v", r["name"], r["action"])
		}
	}
	if denies != 1 {
		t.Fatalf("%d DENY rules, want the one personal_sign text deny", denies)
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
			// v1 is denied outright: its condition must not read a parameter v1 may lack, since a
			// Turnkey policy whose condition errors is skipped, and a skipped DENY fails open.
			if cond == "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD'" {
				denied["ACTIVITY_TYPE_SIGN_RAW_PAYLOAD"] = true
			}
			for _, typ := range []string{"ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "ACTIVITY_TYPE_SIGN_RAW_PAYLOADS"} {
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
	// Transactions: exactly one policy per (contract, function) a transaction tool calls, value 0.
	want := map[string]bool{}
	for k, methods := range txMethods {
		for _, m := range methods {
			want[in.Addrs[k]+" "+hexSelector(k, m)] = true
		}
	}
	got := map[string]bool{}
	for _, p := range turnkeyPolicies(t) {
		cond, _ := p["condition"].(string)
		if !strings.Contains(cond, "ACTIVITY_TYPE_SIGN_TRANSACTION_V2") {
			continue
		}
		if !strings.Contains(cond, "eth.tx.value == 0") || !strings.Contains(cond, "eth.tx.chain_id == "+in.ChainID) {
			t.Fatalf("transaction policy must pin chain and value 0: %s", cond)
		}
		for k := range txMethods {
			for _, m := range txMethods[k] {
				if strings.Contains(cond, "(eth.tx.to == '"+in.Addrs[k]+"' && eth.tx.data[0..10] == '"+hexSelector(k, m)+"')") {
					got[in.Addrs[k]+" "+hexSelector(k, m)] = true
				}
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Turnkey transaction policies allow %v, want exactly %v", got, want)
	}
	if strings.Contains(fmt.Sprint(got), in.Addrs[keySplitRouter]) {
		t.Fatal("no transaction tool calls the SplitRouter")
	}
}

// Every ALLOW on Turnkey names the wallet: the signer user may be able to sign with other keys
// in the organization.
func TestTurnkeyAllowsAreScopedToTheWallet(t *testing.T) {
	for _, p := range turnkeyPolicies(t) {
		if p["effect"] == "EFFECT_ALLOW" && !strings.Contains(p["condition"].(string), "wallet_account.address == '<WALLET>'") {
			t.Fatalf("ALLOW %v is not scoped to the wallet", p["policyName"])
		}
	}
}

// txMethods must list every on-chain method a tool sends, or the policy refuses a real tool;
// and nothing else, or the policy grants more than the tools use.
func TestTxMethodsMatchTheTools(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	re := regexp.MustCompile(`Transact\(auth, "(\w+)"|method:\s+"(\w+)"|method :?= [^\n]*"(\w+)"\s*$`)
	used := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(b), "\n") {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				for _, g := range m[1:] {
					if g != "" {
						used[g] = true
					}
				}
			}
		}
	}
	listed := map[string]bool{}
	for k, ms := range txMethods {
		for _, m := range ms {
			listed[m] = true
			if hexSelector(k, m) == "" {
				t.Fatalf("%s.%s is not in that contract's ABI", k, m)
			}
		}
	}
	if !reflect.DeepEqual(used, listed) {
		t.Fatalf("tools send %v, txMethods lists %v", used, listed)
	}
}

func TestPolicyCLI(t *testing.T) {
	t.Setenv("CHAIN_ID", "84532")
	t.Setenv("MAX_PAYMENT_PER_TX", "")
	addrs := map[string]string{
		"REVIEW_REGISTRY_ADDRESS": "0x00000000000000000000000000000000000000A1", "COMMISSION_ESCROW_ADDRESS": "0x00000000000000000000000000000000000000A2",
		"MERCHANT_REGISTRY_ADDRESS": "0x00000000000000000000000000000000000000A3", "PRODUCT_REGISTRY_ADDRESS": "0x00000000000000000000000000000000000000A4",
		"SPLIT_ROUTER_ADDRESS": "0x00000000000000000000000000000000000000A5", "AGENT_REGISTRY_ADDRESS": "0x00000000000000000000000000000000000000A6",
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

func TestPrivyPolicyBoundsTxValueAndPersonalSign(t *testing.T) {
	var sawTx, sawPersonal bool
	for _, r := range privyRules(t) {
		b, _ := json.Marshal(r["conditions"])
		switch r["method"] {
		case "eth_signTransaction":
			// Privy's ethereum_transaction has only to/value/chain_id (live 2026-10-16), so the function is
			// pinned with an ethereum_calldata condition carrying its ABI fragment.
			sawTx = strings.Contains(string(b), `"field":"value","field_source":"ethereum_transaction","operator":"eq","value":"0x0"`) &&
				strings.Contains(string(b), `"field":"function_name","field_source":"ethereum_calldata","operator":"eq"`) &&
				!strings.Contains(string(b), `"field":"data"`)
		case "personal_sign":
			if r["action"] != "ALLOW" {
				continue // the text DENY is checked in TestPrivyPolicyHasNoWildcard
			}
			// No message condition: Privy evaluates message conditions only on valid UTF-8, so one
			// never matches the binary agent-auth hash (live 2026-10-16, even byte_length gte 0).
			sawPersonal = string(b) == "[]"
		}
	}
	if !sawTx || !sawPersonal {
		t.Fatalf("Privy policy must require tx value 0 and a known function (%v), and allow personal_sign unconditioned (%v)", sawTx, sawPersonal)
	}
}

func TestPrivyTxRulesArePerFunction(t *testing.T) {
	n := 0
	for _, ms := range txMethods {
		n += len(ms)
	}
	got := 0
	for _, r := range privyRules(t) {
		if r["method"] == "eth_signTransaction" {
			got++
		}
	}
	if got != n {
		t.Fatalf("%d Privy transaction rules, want one per tool method (%d)", got, n)
	}
}

// Each Privy calldata condition's ABI fragment must decode to the very selector the tool sends.
func TestPrivyCalldataFragmentsMatchSelectors(t *testing.T) {
	seen := 0
	for _, r := range privyRules(t) {
		for _, c := range r["conditions"].([]any) {
			cond := c.(map[string]any)
			if cond["field_source"] != "ethereum_calldata" {
				continue
			}
			frag, _ := json.Marshal(cond["abi"])
			parsed, err := abi.JSON(bytes.NewReader(frag))
			if err != nil {
				t.Fatalf("rule %v: ABI fragment does not parse: %v", r["name"], err)
			}
			name := cond["value"].(string)
			m, ok := parsed.Methods[name]
			if !ok {
				t.Fatalf("rule %v: fragment has no %s", r["name"], name)
			}
			found := false
			for k, ms := range txMethods {
				for _, want := range ms {
					if want == name && hexutil.Encode(m.ID) == hexSelector(k, want) {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("rule %v: fragment selector %x is not the tool's", r["name"], m.ID)
			}
			seen++
		}
	}
	if seen != 10 {
		t.Fatalf("%d calldata conditions, want 10", seen)
	}
}

// Five policies, so a person can apply them in the Turnkey dashboard: commitments, ERC-3009,
// transactions, and the two raw-payload denies. Each holds one activity kind, because a clause
// that errors makes Turnkey skip the whole policy.
func TestTurnkeyPolicyCount(t *testing.T) {
	ps := turnkeyPolicies(t)
	if len(ps) != 5 {
		names := []any{}
		for _, p := range ps {
			names = append(names, p["policyName"])
		}
		t.Fatalf("%d Turnkey policies %v, want 5", len(ps), names)
	}
}

// Live 2026-10-16: Turnkey compares wallet_account.address case-sensitively against the EIP-55
// form (a lowercase clause matched nothing; the checksummed one signed). How it cases the parsed
// transaction's `to` is undocumented, so that clause accepts both forms of the same address.
func TestTurnkeyAddressCasing(t *testing.T) {
	in := templatePolicyInputs()
	for k := range in.Addrs {
		in.Addrs[k] = "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707"
	}
	in.ChainID, in.USDC, in.MaxValue, in.TurnkeyUserID = "84532", "0x00000000000000000000000000000000000000b1", "5000000", "u1"
	in.Wallet = "0x2ad0aadd90f07263402c01d378740598073e7375"
	b, err := renderPolicy("turnkey", in)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "wallet_account.address == '0x2AD0aAdD90f07263402C01d378740598073e7375'") || strings.Contains(s, "wallet_account.address == '0x2ad0") {
		t.Fatal("the wallet clause must use the checksummed address only")
	}
	if !strings.Contains(s, "(eth.tx.to == '0x5FC8d32690cc91D4c39d9d3abcBD16989F875707' || eth.tx.to == '0x5fc8d32690cc91d4c39d9d3abcbd16989f875707')") {
		t.Fatal("the transaction `to` clause must accept both forms of the address")
	}
	if !strings.Contains(s, "verifying_contract == '0x5fc8d32690cc91d4c39d9d3abcbd16989f875707'") {
		t.Fatal("EIP-712 fields stay lowercase (Turnkey's documented form, confirmed live)")
	}
}
