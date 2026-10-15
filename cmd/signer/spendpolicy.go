package main

import (
	"fmt"
	"math/big"
	"os"
	"strings"
)

// spendPolicy is the owner's ceiling on pay_for_product, read from the environment at boot
// so the model cannot talk its way past it.
type spendPolicy struct {
	maxPerTx  *big.Int        // nil = no cap
	merchants map[string]bool // empty = any merchant
}

var signerSpendPolicy spendPolicy

// spendPolicyFromEnv parses MAX_PAYMENT_PER_TX (USDC base units) and MERCHANT_ALLOWLIST
// (comma-separated decimal merchant ids).
func spendPolicyFromEnv() (spendPolicy, error) {
	var p spendPolicy
	if v := strings.TrimSpace(os.Getenv("MAX_PAYMENT_PER_TX")); v != "" {
		n, ok := new(big.Int).SetString(v, 10)
		if !ok || n.Sign() < 0 {
			return p, fmt.Errorf("MAX_PAYMENT_PER_TX %q: want a non-negative integer in USDC base units", v)
		}
		p.maxPerTx = n
	}
	if v := strings.TrimSpace(os.Getenv("MERCHANT_ALLOWLIST")); v != "" {
		p.merchants = map[string]bool{}
		for _, raw := range strings.Split(v, ",") {
			n, ok := new(big.Int).SetString(strings.TrimSpace(raw), 10)
			if !ok {
				return p, fmt.Errorf("MERCHANT_ALLOWLIST entry %q: want a decimal merchant id", raw)
			}
			p.merchants[n.String()] = true
		}
	}
	return p, nil
}

// check refuses a purchase the policy does not allow. liveAmount is the merchant's current
// price, maxAmount the caller's max_amount (may be empty), merchantID from the token.
func (p spendPolicy) check(liveAmount, maxAmount, merchantID string) error {
	if len(p.merchants) > 0 && !p.merchants[canonicalDecimal(merchantID)] {
		return fmt.Errorf("merchant %s is not in MERCHANT_ALLOWLIST", merchantID)
	}
	if p.maxPerTx == nil {
		return nil
	}
	if strings.TrimSpace(maxAmount) == "" {
		return fmt.Errorf("MAX_PAYMENT_PER_TX is set, so max_amount is required on every pay_for_product call")
	}
	live, ok := new(big.Int).SetString(liveAmount, 10)
	if !ok {
		return fmt.Errorf("invalid live amount %q", liveAmount)
	}
	if live.Cmp(p.maxPerTx) > 0 {
		return fmt.Errorf("live price %s exceeds MAX_PAYMENT_PER_TX %s", live, p.maxPerTx)
	}
	return nil
}

// canonicalDecimal strips leading zeros so "007" and "7" name the same merchant; a non-numeric
// input is returned as-is and will simply not match.
func canonicalDecimal(id string) string {
	if n, ok := new(big.Int).SetString(strings.TrimSpace(id), 10); ok {
		return n.String()
	}
	return id
}
