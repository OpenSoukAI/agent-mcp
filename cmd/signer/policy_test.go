package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func templatePath(provider string) string {
	return "../../docs/signer-policies/" + provider + "." + policyVersion + ".json"
}

func TestPolicyTemplatesAreGolden(t *testing.T) {
	for _, p := range []string{"turnkey", "privy", "cdp"} {
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
	// cdp: one signEvmTypedData accept rule per primary type, keyed by the typed-data field's own
	// primaryType (not string-counted, since CDP's JSON nests it under criteria).
	cdpDoc := decodePolicy(t, "cdp", in)
	counts := map[string]int{}
	for _, r := range cdpDoc["rules"].([]any) {
		rule := r.(map[string]any)
		if rule["operation"] != "signEvmTypedData" || rule["action"] != "accept" {
			continue
		}
		for _, c := range rule["criteria"].([]any) {
			cond := c.(map[string]any)
			if cond["type"] != "evmTypedDataField" {
				continue
			}
			types := cond["types"].(map[string]any)
			counts[types["primaryType"].(string)]++
		}
	}
	for _, spec := range append(allSpecs, domainSpec{primary: erc3009ReceiveAuthorizationType}) {
		want := 1
		if spec == specAgentWalletSet {
			want = len(in.AgentIDs)
		}
		if counts[spec.primary] != want {
			t.Fatalf("cdp: %s counted %d signEvmTypedData accept rules, want %d", spec.primary, counts[spec.primary], want)
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

func cdpRules(t *testing.T) []map[string]any {
	var out []map[string]any
	for _, r := range decodePolicy(t, "cdp", templatePolicyInputs())["rules"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

// CDP cannot restrict signEvmHash, signEvmMessage, sendEvmTransaction, prepareUserOperation or
// sendUserOperation by a criterion that would distinguish the signer's own traffic from an
// attacker's (a policy can't inspect a raw digest, free text, or an already-built op), so each is
// rejected outright. CDP's CreatePolicyBodySchema still requires at least one criterion for every
// operation except signEvmHash, so the other four carry a criterion that always matches rather
// than one that restricts anything. Every accept rule must instead carry at least one criterion
// that actually restricts something.
func TestCDPPolicyRejectsUnrestrictableOps(t *testing.T) {
	alwaysMatchMessage := []any{map[string]any{"type": "evmMessage", "match": "(?s).*"}}
	alwaysMatchEthValue := []any{map[string]any{"type": "ethValue", "ethValue": "0", "operator": ">="}}
	wantCriteria := map[string][]any{
		"signEvmHash":          {},
		"signEvmMessage":       alwaysMatchMessage,
		"sendEvmTransaction":   alwaysMatchEthValue,
		"prepareUserOperation": alwaysMatchEthValue,
		"sendUserOperation":    alwaysMatchEthValue,
	}
	seen := map[string]int{}
	for _, r := range cdpRules(t) {
		criteria, _ := r["criteria"].([]any)
		op, _ := r["operation"].(string)
		switch r["action"] {
		case "reject":
			want, ok := wantCriteria[op]
			if !ok {
				t.Fatalf("unexpected reject rule for operation %s", op)
			}
			seen[op]++
			if !reflect.DeepEqual(criteria, want) {
				t.Fatalf("reject rule for %s has criteria %v, want %v", op, criteria, want)
			}
		case "accept":
			if len(criteria) == 0 {
				t.Fatalf("accept rule for %s has empty criteria", op)
			}
		default:
			t.Fatalf("rule %v has action %v", r, r["action"])
		}
	}
	for op := range wantCriteria {
		if seen[op] != 1 {
			t.Fatalf("want exactly one reject rule for %s, saw %d", op, seen[op])
		}
	}
}

// CDP's EvmDataCriterion requires every condition to be met, so a single rule can never name more
// than one function — each (contract, method) pair a transaction tool calls gets its own
// signEvmTransaction rule, scoped to that contract's address, value 0, and an evmData ABI
// condition naming exactly that one method.
func TestCDPTxRulesMatchTxMethods(t *testing.T) {
	in := templatePolicyInputs()
	type pair struct {
		k protocolKey
		m string
	}
	seen := map[pair]bool{}
	for _, r := range cdpRules(t) {
		if r["operation"] != "signEvmTransaction" {
			continue
		}
		var addrCrit, valueCrit, dataCrit map[string]any
		for _, c := range r["criteria"].([]any) {
			cond := c.(map[string]any)
			switch cond["type"] {
			case "evmAddress":
				addrCrit = cond
			case "ethValue":
				valueCrit = cond
			case "evmData":
				dataCrit = cond
			}
		}
		if addrCrit == nil || valueCrit == nil || dataCrit == nil {
			t.Fatalf("tx rule %v is missing an evmAddress, ethValue, or evmData criterion", r)
		}
		if valueCrit["ethValue"] != "0" || valueCrit["operator"] != "==" {
			t.Fatalf("tx rule %v must require ethValue == \"0\"", r)
		}
		addrs, _ := addrCrit["addresses"].([]any)
		if len(addrs) != 1 {
			t.Fatalf("tx rule %v must name exactly one address", r)
		}
		addr, _ := addrs[0].(string)
		var k protocolKey
		found := false
		for kk, a := range in.Addrs {
			if a == addr {
				k, found = kk, true
				break
			}
		}
		if !found {
			t.Fatalf("tx rule address %s is not a known protocol contract", addr)
		}
		conds, _ := dataCrit["conditions"].([]any)
		if len(conds) != 1 {
			t.Fatalf("tx rule %v evmData must have exactly one condition (CDP ANDs all of them), got %d", r, len(conds))
		}
		m, _ := conds[0].(map[string]any)["function"].(string)
		p := pair{k, m}
		if seen[p] {
			t.Fatalf("contract %s method %s has more than one signEvmTransaction rule", k, m)
		}
		seen[p] = true
		listed := false
		for _, want := range txMethods[k] {
			if want == m {
				listed = true
			}
		}
		if !listed {
			t.Fatalf("tx rule names %s.%s, which is not in txMethods", k, m)
		}
	}
	want := 0
	for k, ms := range txMethods {
		for _, m := range ms {
			want++
			if !seen[pair{k, m}] {
				t.Fatalf("no signEvmTransaction rule for %s.%s", k, m)
			}
		}
	}
	if len(seen) != want {
		t.Fatalf("%d signEvmTransaction rules, want exactly %d (one per contract+method)", len(seen), want)
	}
}

// CDP's own description/rules-count limits: a description it will accept, and at most 100 rules.
func TestCDPPolicyShape(t *testing.T) {
	doc := decodePolicy(t, "cdp", templatePolicyInputs())
	if doc["scope"] != "account" {
		t.Fatalf("scope = %v, want account", doc["scope"])
	}
	desc, _ := doc["description"].(string)
	if !regexp.MustCompile(`^[A-Za-z0-9 ,.]{1,50}$`).MatchString(desc) {
		t.Fatalf("description %q does not match CDP's allowed pattern", desc)
	}
	rules, _ := doc["rules"].([]any)
	if len(rules) == 0 || len(rules) > 100 {
		t.Fatalf("%d rules, want 1-100", len(rules))
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

// zeroABIValue is the harmless zero argument for ABI type t. The ten transaction methods take
// only flat types (abiFragment's own comment), so only those need handling; a uint/int wider than
// 64 bits needs an actual *big.Int (reflect.Zero of that Go type is a nil pointer, which the ABI
// packer cannot encode).
func zeroABIValue(t abi.Type) (any, error) {
	switch t.T {
	case abi.UintTy, abi.IntTy:
		if t.Size > 64 {
			return big.NewInt(0), nil
		}
		return reflect.Zero(t.GetType()).Interface(), nil
	case abi.AddressTy:
		return common.Address{}, nil
	case abi.BoolTy:
		return false, nil
	case abi.StringTy:
		return "", nil
	case abi.FixedBytesTy:
		return reflect.Zero(t.GetType()).Interface(), nil
	case abi.BytesTy:
		return []byte{}, nil
	default:
		return nil, fmt.Errorf("zeroABIValue: unsupported ABI type %s", t.String())
	}
}

// zeroArgsCalldata packs method m on contract k's ABI with every argument at its zero value: real,
// ABI-decodable calldata for a call to m that happens to mean nothing, for building a self-test or
// live-test transaction without caring what the method does with the values. Used by
// TestZeroArgsCalldataUnpacks here and by provider_live_test.go's CDP "allowed" leg, which needs
// real calldata per (contract, method) because CDP's policy ABI-decodes it.
func zeroArgsCalldata(k protocolKey, m string) ([]byte, error) {
	a, ok := txABIs[k]
	if !ok {
		return nil, fmt.Errorf("zeroArgsCalldata: no ABI for %s", k)
	}
	method, ok := a.Methods[m]
	if !ok {
		return nil, fmt.Errorf("zeroArgsCalldata: %s has no method %s", k, m)
	}
	args := make([]any, len(method.Inputs))
	for i, in := range method.Inputs {
		v, err := zeroABIValue(in.Type)
		if err != nil {
			return nil, fmt.Errorf("zeroArgsCalldata: %s.%s arg %s: %w", k, m, in.Name, err)
		}
		args[i] = v
	}
	return a.Pack(m, args...)
}

// Every (contract, method) txMethods lists must pack with zero arguments and ABI-decode back
// against its own method. This runs without live env, unlike the real target (CDP's policy
// engine): it would have caught the bug where the "allowed" live-test leg built calldata as a
// selector padded with 64 arbitrary zero bytes, which cannot decode for a method with more than
// one word of arguments (publishReviewWithEscrowProof, grantRole, revokeRole, setCommission,
// setProductActive: 3 words each) or a dynamic type (addProduct's trailing string).
func TestZeroArgsCalldataUnpacks(t *testing.T) {
	for k, ms := range txMethods {
		for _, m := range ms {
			t.Run(string(k)+"."+m, func(t *testing.T) {
				data, err := zeroArgsCalldata(k, m)
				if err != nil {
					t.Fatalf("zeroArgsCalldata(%s, %s): %v", k, m, err)
				}
				method := txABIs[k].Methods[m]
				if len(data) < 4 || !bytes.Equal(data[:4], method.ID) {
					t.Fatalf("%s.%s: calldata selector %x, want %x", k, m, data, method.ID)
				}
				if _, err := method.Inputs.Unpack(data[4:]); err != nil {
					t.Fatalf("%s.%s: calldata does not ABI-decode against its own method: %v", k, m, err)
				}
			})
		}
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
	code, out, e := run("--provider", "privy", "--usdc", "0x00000000000000000000000000000000000000B1", "--max-payment", "5000000", "--agent-id", "12")
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
	cdpCode, cdpOut, cdpErr := run("--provider", "cdp", "--template")
	if cdpCode != 0 {
		t.Fatalf("cdp template exit %d: %s", cdpCode, cdpErr)
	}
	want, err := os.ReadFile(templatePath("cdp"))
	if err != nil || cdpOut != string(want) {
		t.Fatalf("cdp template output does not match docs/signer-policies/cdp.%s.json (%v)", policyVersion, err)
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

func awsPolicyInputs(ids ...string) policyInputs {
	in := templatePolicyInputs()
	for k := range in.Addrs {
		in.Addrs[k] = "0x00000000000000000000000000000000000000a1"
	}
	in.ChainID, in.USDC, in.MaxValue, in.TurnkeyUserID = "84532", "0x00000000000000000000000000000000000000b1", "5000000", "u1"
	in.Wallet = "0x2ad0aadd90f07263402c01d378740598073e7375"
	in.AgentIDs = ids
	return in
}

// AgentWalletSet is allowed only for the agent ids the operator names; with none, not at all.
func TestPoliciesPinAgentWalletSetToAgentIDs(t *testing.T) {
	for _, p := range []string{"turnkey", "privy", "cdp"} {
		none, err := renderPolicy(p, awsPolicyInputs())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(none), "AgentWalletSet") {
			t.Fatalf("%s: without agent ids the policy must not allow AgentWalletSet", p)
		}
		two, err := renderPolicy(p, awsPolicyInputs("12", "34"))
		if err != nil {
			t.Fatal(err)
		}
		s := string(two)
		if p == "turnkey" {
			if !strings.Contains(s, "(eth.eip_712.message['agentId'] == 12 || eth.eip_712.message['agentId'] == 34)") {
				t.Fatalf("turnkey: AgentWalletSet must be pinned to agents 12 and 34:\n%s", s)
			}
			continue
		}
		if p == "cdp" {
			pinned := map[string]bool{}
			for _, r := range decodePolicy(t, "cdp", awsPolicyInputs("12", "34"))["rules"].([]any) {
				rule := r.(map[string]any)
				if rule["operation"] != "signEvmTypedData" {
					continue
				}
				for _, c := range rule["criteria"].([]any) {
					cond := c.(map[string]any)
					if cond["type"] != "evmTypedDataField" {
						continue
					}
					types := cond["types"].(map[string]any)
					if types["primaryType"] != "AgentWalletSet" {
						continue
					}
					for _, cc := range cond["conditions"].([]any) {
						ccond := cc.(map[string]any)
						if ccond["path"] == "agentId" {
							if ccond["operator"] != "==" {
								t.Fatalf("cdp: agentId must be compared with ==, got %v", ccond["operator"])
							}
							pinned[ccond["value"].(string)] = true
						}
					}
				}
			}
			if len(pinned) != 2 || !pinned["12"] || !pinned["34"] {
				t.Fatalf("cdp: want one AgentWalletSet rule per agent id, got %v", pinned)
			}
			continue
		}
		pinned := map[string]bool{}
		for _, r := range decodePolicy(t, "privy", awsPolicyInputs("12", "34"))["rules"].([]any) {
			rule := r.(map[string]any)
			if !strings.Contains(rule["name"].(string), "AgentWalletSet") {
				continue
			}
			for _, c := range rule["conditions"].([]any) {
				cond := c.(map[string]any)
				if cond["field"] == "agentId" {
					if cond["operator"] != "eq" {
						t.Fatalf("privy: agentId must be compared with eq, got %v", cond["operator"])
					}
					pinned[cond["value"].(string)] = true
				}
			}
		}
		if len(pinned) != 2 || !pinned["12"] || !pinned["34"] {
			t.Fatalf("privy: want one AgentWalletSet rule per agent id, got %v", pinned)
		}
	}
}

func TestPolicyCLIAgentIDs(t *testing.T) {
	t.Setenv("CHAIN_ID", "84532")
	for _, k := range []string{"REVIEW_REGISTRY_ADDRESS", "COMMISSION_ESCROW_ADDRESS", "MERCHANT_REGISTRY_ADDRESS", "PRODUCT_REGISTRY_ADDRESS", "SPLIT_ROUTER_ADDRESS", "AGENT_REGISTRY_ADDRESS"} {
		t.Setenv(k, "0x00000000000000000000000000000000000000A1")
	}
	resetAddressCache()
	t.Cleanup(resetAddressCache)
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runPolicyCLI(context.Background(), append([]string{"--provider", "privy", "--usdc", "0x00000000000000000000000000000000000000B1", "--max-payment", "5"}, args...), &out, &errb)
		return code, out.String(), errb.String()
	}
	if code, _, e := run("--agent-id", "12,x"); code == 0 || !strings.Contains(e, "--agent-id") {
		t.Fatalf("a non-decimal agent id must be refused, got %d %q", code, e)
	}
	if code, out, e := run("--agent-id", "12, 34"); code != 0 || !strings.Contains(out, `"value": "34"`) {
		t.Fatalf("want agent 34 pinned, got %d %q", code, e)
	}
	if code, out, e := run(); code != 0 || strings.Contains(out, "AgentWalletSet") || !strings.Contains(e, "--agent-id") {
		t.Fatalf("without --agent-id: want no AgentWalletSet and a note on stderr, got %d %q", code, e)
	}
}
