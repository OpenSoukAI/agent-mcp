package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
)

// Provider policies, generated from the same domainSpec table and typed-data builders the tools
// sign with, so a policy cannot drift from what the signer sends. The committed templates under
// docs/signer-policies are this generator's --template output; TestPolicyTemplatesAreGolden
// keeps them equal.

var allSpecs = []domainSpec{specReview, specVote, specCashbackRate, specIntentAccess, specIntentMark, specIntentSkip, specTelegramLink, specCharge}

// txContracts are the contracts the transaction tools call, and txMethods the functions on each.
// The policy allows a transaction only to one of these functions, with no ETH value: an agent
// wallet with merchant rights must not reach a function no tool uses. TestTxMethodsMatchTheTools
// checks this against the tools' own Transact calls.
var txContracts = []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry}

var txMethods = map[protocolKey][]string{
	keyReviewRegistry:   {"publishReviewWithEscrowProof", "updateReviewContent"},
	keyEscrow:           {"bind", "triggerSettleFallback"},
	keyMerchantRegistry: {"setActive", "grantRole", "revokeRole"},
	keyProductRegistry:  {"addProduct", "setCommission", "setProductActive"},
}

var txABIs = map[protocolKey]*abi.ABI{
	keyReviewRegistry: &reviewRegistryABI, keyEscrow: &commissionEscrowABI,
	keyMerchantRegistry: &merchantRegistryABI, keyProductRegistry: &productRegistryABI,
}

// hexSelector is the 4-byte selector of method m on contract k, 0x-hex, or "" if the tools' ABI
// for k has no such method.
func hexSelector(k protocolKey, m string) string {
	a, ok := txABIs[k]
	if !ok {
		return ""
	}
	method, ok := a.Methods[m]
	if !ok {
		return ""
	}
	return hexutil.Encode(method.ID)
}

type policyInputs struct {
	ChainID       string // decimal
	Addrs         map[protocolKey]string
	USDC          string
	MaxValue      string // USDC base units, the ReceiveWithAuthorization ceiling
	TurnkeyUserID string
	Wallet        string // Turnkey: the wallet account address every ALLOW is scoped to
}

func templatePolicyInputs() policyInputs {
	addrs := map[protocolKey]string{}
	for _, k := range []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry, keySplitRouter} {
		addrs[k] = "<" + string(k) + ">"
	}
	return policyInputs{ChainID: "<CHAIN_ID>", Addrs: addrs, USDC: "<USDC>", MaxValue: "<MAX_PAYMENT>", TurnkeyUserID: "<TURNKEY_SIGNER_USER_ID>", Wallet: "<WALLET>"}
}

const zero32 = "0x0000000000000000000000000000000000000000000000000000000000000000"

// sampleTypedData is spec's typed data built by the real builder from a zero payload. Only its
// types are used: they do not depend on the values.
func sampleTypedData(spec domainSpec) apitypes.TypedData {
	return specTypedData(spec, 1, common.Address{}.Hex())
}

// specTypedData is a zero-payload commitment of spec's type in its own domain on chainID at
// verifying.
func specTypedData(spec domainSpec, chainID int64, verifying string) apitypes.TypedData {
	d := commitmentDomain{Name: spec.name, Version: spec.version, ChainID: chainID, VerifyingContract: verifying}
	var td apitypes.TypedData
	var err error
	switch spec.primary {
	case specReview.primary:
		td, err = reviewTypedData(reviewCommitmentPayload{Domain: d, Message: commitmentMessage{AgentID: "0", MerchantID: "0", ProductID: zero32, ContentHash: zero32, Nonce: "0", Expiry: "0"}})
	case specVote.primary:
		td, err = voteTypedData(voteCommitmentPayload{Domain: d, Message: voteCommitmentMessage{AgentID: "0", EscrowID: "0", VotesHash: zero32, Nonce: "0", Expiry: "0"}})
	case specCashbackRate.primary:
		td, err = cashbackRateTypedData(cashbackRateCommitmentPayload{Domain: d, Message: cashbackRateCommitmentMessage{AgentID: "0", CashbackOfCommissionBps: "0", Nonce: zero32, Expiry: "0"}})
	case specIntentAccess.primary:
		td, err = intentAccessTypedData(intentAccessCommitmentPayload{Domain: d, Message: intentAccessCommitmentMessage{AgentID: "0", Nonce: zero32, Expiry: "0"}})
	case specIntentMark.primary:
		td, err = intentMarkTypedData(intentMarkCommitmentPayload{Domain: d, Message: intentMarkCommitmentMessage{AgentID: "0", IntentID: "x", Result: "x", Nonce: zero32, Expiry: "0"}})
	case specIntentSkip.primary:
		td, err = intentSkipTypedData(intentSkipCommitmentPayload{Domain: d, Message: intentSkipCommitmentMessage{AgentID: "0", IntentID: "x", Reason: "x", Nonce: zero32, Expiry: "0"}})
	case specTelegramLink.primary:
		td, err = telegramLinkTypedData(telegramLinkCommitmentPayload{Domain: d, Message: telegramLinkCommitmentMessage{AgentID: "0", Nonce: zero32, Expiry: "0"}})
	case specCharge.primary:
		td, err = chargeTypedData(common.Address{}, [32]byte{}, big.NewInt(0), [32]byte{}, chainID, common.HexToAddress(verifying))
	default:
		panic("sampleTypedData: no builder for " + spec.primary)
	}
	if err != nil {
		panic(fmt.Sprintf("sampleTypedData(%s): %v", spec.primary, err))
	}
	return td
}

func sampleReceiveTypedData() apitypes.TypedData {
	zero := common.Address{}.Hex()
	td, err := erc3009ReceiveTypedData(evm.ExactEIP3009Authorization{From: zero, To: zero, Value: "0", ValidAfter: "0", ValidBefore: "0", Nonce: zero32}, big.NewInt(1), zero, "USDC", "2")
	if err != nil {
		panic(err)
	}
	return td
}

func providerTypes(td apitypes.TypedData) any {
	m, err := providerTypedDataJSON(td, "primary_type")
	if err != nil {
		panic(err)
	}
	return m["types"]
}

// firstUintField names td's first uint field: a Privy message condition needs one to bind the
// rule to the primary type and its exact types.
func firstUintField(td apitypes.TypedData) string {
	for _, f := range td.Types[td.PrimaryType] {
		if strings.HasPrefix(f.Type, "uint") {
			return f.Name
		}
	}
	panic("no uint field in " + td.PrimaryType)
}

func turnkeyPolicyDoc(in policyInputs) map[string]any {
	consensus := "approvers.any(user, user.id == '" + in.TurnkeyUserID + "')"
	// Scoped to the wallet too: the signer user may be able to sign with other keys in the org.
	wallet := " && wallet_account.address == '" + in.Wallet + "'"
	allow := func(name, cond string) map[string]any {
		return map[string]any{"policyName": "opensouk-v1 " + name, "effect": "EFFECT_ALLOW", "consensus": consensus, "condition": cond + wallet, "notes": "Generated by referrer-signer policy (REF-492)."}
	}
	const typed = "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && activity.params.encoding == 'PAYLOAD_ENCODING_EIP712'"
	var ps []map[string]any
	for _, spec := range allSpecs {
		ps = append(ps, allow("allow "+spec.primary, typed+
			" && eth.eip_712.primary_type == '"+spec.primary+"'"+
			" && eth.eip_712.domain.name == '"+spec.name+"' && eth.eip_712.domain.version == '"+spec.version+"'"+
			" && eth.eip_712.domain.chain_id == "+in.ChainID+
			" && eth.eip_712.domain.verifying_contract == '"+in.Addrs[spec.contract]+"'"))
	}
	ps = append(ps, allow("allow "+erc3009ReceiveAuthorizationType, typed+
		" && eth.eip_712.primary_type == '"+erc3009ReceiveAuthorizationType+"'"+
		" && eth.eip_712.domain.chain_id == "+in.ChainID+
		" && eth.eip_712.domain.verifying_contract == '"+in.USDC+"'"+
		" && eth.eip_712.message['to'] == '"+in.Addrs[keySplitRouter]+"'"+
		" && eth.eip_712.message['value'] <= "+in.MaxValue))
	for _, k := range txContracts {
		for _, m := range txMethods[k] {
			ps = append(ps, allow("allow "+string(k)+"."+m, "activity.type == 'ACTIVITY_TYPE_SIGN_TRANSACTION_V2' && eth.tx.chain_id == "+in.ChainID+
				" && eth.tx.value == 0 && eth.tx.to == '"+in.Addrs[k]+"' && eth.tx.data[0..10] == '"+hexSelector(k, m)+"'"))
		}
	}
	// A raw payload that is not EIP-712 can be any typed-data or transaction signature, so the
	// policies above would mean nothing if it were allowed. Deny them explicitly, for every user.
	// v1 is denied outright: a Turnkey policy whose condition errors is skipped, so a DENY must
	// not read a parameter (encoding) an activity type may lack.
	deny := func(name, cond string) map[string]any {
		return map[string]any{"policyName": "opensouk-v1 deny raw " + name, "effect": "EFFECT_DENY", "condition": cond, "notes": "Generated by referrer-signer policy (REF-492)."}
	}
	ps = append(ps, deny("SIGN_RAW_PAYLOAD", "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD'"))
	for _, typ := range []string{"ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", "ACTIVITY_TYPE_SIGN_RAW_PAYLOADS"} {
		ps = append(ps, deny(strings.TrimPrefix(typ, "ACTIVITY_TYPE_"), "activity.type == '"+typ+"' && activity.params.encoding != 'PAYLOAD_ENCODING_EIP712'"))
	}
	return map[string]any{"provider": "turnkey", "version": "v1", "policies": ps}
}

func privyPolicyDoc(in policyInputs) map[string]any {
	domainConds := func(verifying string) []any {
		return []any{
			map[string]any{"field_source": "ethereum_typed_data_domain", "field": "chainId", "operator": "eq", "value": in.ChainID},
			map[string]any{"field_source": "ethereum_typed_data_domain", "field": "verifyingContract", "operator": "eq", "value": verifying},
		}
	}
	msgCond := func(td apitypes.TypedData, field, op, value string) map[string]any {
		return map[string]any{"field_source": "ethereum_typed_data_message", "typed_data": map[string]any{"types": providerTypes(td), "primary_type": td.PrimaryType},
			"field": field, "operator": op, "value": value}
	}
	var rules []any
	for _, spec := range allSpecs {
		td := sampleTypedData(spec)
		rules = append(rules, map[string]any{"name": "allow " + spec.primary, "method": "eth_signTypedData_v4", "action": "ALLOW",
			"conditions": append(domainConds(in.Addrs[spec.contract]), msgCond(td, firstUintField(td), "gte", "0"))})
	}
	rtd := sampleReceiveTypedData()
	rules = append(rules, map[string]any{"name": "allow " + erc3009ReceiveAuthorizationType, "method": "eth_signTypedData_v4", "action": "ALLOW",
		"conditions": append(domainConds(in.USDC), msgCond(rtd, "to", "eq", in.Addrs[keySplitRouter]), msgCond(rtd, "value", "lte", in.MaxValue))})
	for _, k := range txContracts {
		for _, m := range txMethods[k] {
			rules = append(rules, map[string]any{"name": "allow " + string(k) + "." + m, "method": "eth_signTransaction", "action": "ALLOW",
				"conditions": []any{
					map[string]any{"field_source": "ethereum_transaction", "field": "chain_id", "operator": "eq", "value": in.ChainID},
					map[string]any{"field_source": "ethereum_transaction", "field": "to", "operator": "eq", "value": in.Addrs[k]},
					map[string]any{"field_source": "ethereum_transaction", "field": "value", "operator": "eq", "value": "0x0"},
					map[string]any{"field_source": "ethereum_transaction", "field": "data", "operator": "starts_with", "value": hexSelector(k, m)},
				}})
		}
	}
	// personal_sign cannot collide with a typed-data or transaction hash (EIP-191 prefix). Agent
	// auth, the merchant REST tools' request signature, signs a 32-byte hash and nothing else.
	rules = append(rules, map[string]any{"name": "allow agent-auth personal_sign", "method": "personal_sign", "action": "ALLOW",
		"conditions": []any{map[string]any{"field_source": "message", "field": "byte_length", "operator": "eq", "value": "32"}}})
	return map[string]any{"version": "1.0", "name": "opensouk-signer-v1", "chain_type": "ethereum", "rules": rules}
}

// renderPolicy is the provider's policy document as indented JSON with a trailing newline.
func renderPolicy(provider string, in policyInputs) ([]byte, error) {
	var doc map[string]any
	switch provider {
	case "turnkey":
		doc = turnkeyPolicyDoc(in)
	case "privy":
		doc = privyPolicyDoc(in)
	default:
		return nil, fmt.Errorf("unknown provider %q: use turnkey or privy", provider)
	}
	// No HTML escaping: a Turnkey condition is pasted as written, and "\u0026\u0026" is not "&&".
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// runPolicyCLI is `referrer-signer policy`: print a provider policy for this signer's chain, with
// the contract addresses resolved the way the tools resolve them.
func runPolicyCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	provider := fs.String("provider", "", "turnkey or privy")
	template := fs.Bool("template", false, "print the committed template, with placeholders")
	usdc := fs.String("usdc", "", "USDC contract on this chain (default USDC_ADDRESS)")
	maxPay := fs.String("max-payment", "", "ReceiveWithAuthorization ceiling in USDC base units (default MAX_PAYMENT_PER_TX)")
	tkUser := fs.String("turnkey-user-id", "", "Turnkey user id of the signer's API user (turnkey only)")
	wallet := fs.String("wallet", "", "Turnkey wallet account address the policies are scoped to (turnkey only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "referrer-signer policy: "+format+"\n", a...)
		return 1
	}
	if *provider != "turnkey" && *provider != "privy" {
		return fail("--provider must be turnkey or privy")
	}
	in := templatePolicyInputs()
	if !*template {
		chainID, err := configuredChainID()
		if err != nil {
			return fail("%v", err)
		}
		in.ChainID = strconv.FormatInt(chainID, 10)
		for k := range in.Addrs {
			a, err := resolveAddress(ctx, chainID, k)
			if err != nil {
				return fail("%v", err)
			}
			in.Addrs[k] = strings.ToLower(a.Hex())
		}
		u := strings.TrimSpace(*usdc)
		if u == "" {
			u = strings.TrimSpace(os.Getenv("USDC_ADDRESS"))
		}
		if !common.IsHexAddress(u) {
			return fail("--usdc (or USDC_ADDRESS) must be the USDC contract address on chain %d", chainID)
		}
		in.USDC = strings.ToLower(common.HexToAddress(u).Hex())
		m := strings.TrimSpace(*maxPay)
		if m == "" {
			m = strings.TrimSpace(os.Getenv("MAX_PAYMENT_PER_TX"))
		}
		if n, ok := new(big.Int).SetString(m, 10); !ok || n.Sign() < 0 {
			return fail("the policy needs a payment ceiling: pass --max-payment or set MAX_PAYMENT_PER_TX (USDC base units)")
		}
		in.MaxValue = m
		if *provider == "turnkey" {
			if strings.TrimSpace(*tkUser) == "" {
				return fail("--turnkey-user-id is required: the Turnkey user id of the signer's API user")
			}
			in.TurnkeyUserID = strings.TrimSpace(*tkUser)
			if !common.IsHexAddress(*wallet) {
				return fail("--wallet is required: the Turnkey wallet account address the signer signs with")
			}
			in.Wallet = strings.ToLower(common.HexToAddress(*wallet).Hex())
		}
	}
	b, err := renderPolicy(*provider, in)
	if err != nil {
		return fail("%v", err)
	}
	_, _ = stdout.Write(b)
	return 0
}
