package main

import (
	"strings"
	"testing"
)

func TestSpendPolicyFromEnv_Empty(t *testing.T) {
	t.Setenv("MAX_PAYMENT_PER_TX", "")
	t.Setenv("MERCHANT_ALLOWLIST", "")
	p, err := spendPolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if p.maxPerTx != nil || len(p.merchants) != 0 {
		t.Fatalf("empty env must yield an empty policy, got %+v", p)
	}
	if err := p.check("999999999999", "", "42"); err != nil {
		t.Fatalf("empty policy must not refuse: %v", err)
	}
}

func TestSpendPolicyFromEnv_RejectsGarbage(t *testing.T) {
	t.Setenv("MERCHANT_ALLOWLIST", "")
	t.Setenv("MAX_PAYMENT_PER_TX", "5 USDC")
	if _, err := spendPolicyFromEnv(); err == nil {
		t.Fatal("want parse error")
	}
	t.Setenv("MAX_PAYMENT_PER_TX", "-1")
	if _, err := spendPolicyFromEnv(); err == nil {
		t.Fatal("want error for negative cap")
	}
	t.Setenv("MAX_PAYMENT_PER_TX", "")
	t.Setenv("MERCHANT_ALLOWLIST", "7, x")
	if _, err := spendPolicyFromEnv(); err == nil {
		t.Fatal("want error for non-numeric merchant id")
	}
}

func TestSpendPolicy_CapRefusesAbove(t *testing.T) {
	t.Setenv("MAX_PAYMENT_PER_TX", "50000000")
	t.Setenv("MERCHANT_ALLOWLIST", "")
	p, err := spendPolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	err = p.check("50000001", "50000001", "1")
	if err == nil || !strings.Contains(err.Error(), "MAX_PAYMENT_PER_TX") {
		t.Fatalf("want cap refusal, got %v", err)
	}
	if err := p.check("50000000", "50000000", "1"); err != nil {
		t.Fatalf("at the cap must pass: %v", err)
	}
}

func TestSpendPolicy_CapRequiresMaxAmount(t *testing.T) {
	t.Setenv("MAX_PAYMENT_PER_TX", "50000000")
	t.Setenv("MERCHANT_ALLOWLIST", "")
	p, err := spendPolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	err = p.check("1", "", "1")
	if err == nil || !strings.Contains(err.Error(), "max_amount is required") {
		t.Fatalf("want max_amount required, got %v", err)
	}
}

func TestSpendPolicy_CapBeatsLargerMaxAmount(t *testing.T) {
	t.Setenv("MAX_PAYMENT_PER_TX", "50000000")
	t.Setenv("MERCHANT_ALLOWLIST", "")
	p, err := spendPolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	// The model passed a max_amount above the owner's cap; the cap still wins.
	if err := p.check("60000000", "70000000", "1"); err == nil {
		t.Fatal("cap must refuse even when max_amount would allow it")
	}
}

func TestSpendPolicy_MerchantAllowlist(t *testing.T) {
	t.Setenv("MAX_PAYMENT_PER_TX", "")
	t.Setenv("MERCHANT_ALLOWLIST", "7,12")
	p, err := spendPolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.check("1", "", "12"); err != nil {
		t.Fatalf("listed merchant must pass: %v", err)
	}
	err = p.check("1", "", "13")
	if err == nil || !strings.Contains(err.Error(), "MERCHANT_ALLOWLIST") || !strings.Contains(err.Error(), "13") {
		t.Fatalf("want allowlist refusal naming the merchant, got %v", err)
	}
}

func TestSpendPolicy_MerchantIdsNormalised(t *testing.T) {
	t.Setenv("MAX_PAYMENT_PER_TX", "")
	t.Setenv("MERCHANT_ALLOWLIST", "007, 12")
	p, err := spendPolicyFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	// The token carries the canonical decimal form; a zero-padded allowlist entry must still match.
	if err := p.check("1", "", "7"); err != nil {
		t.Fatalf("allowlist entry 007 must match merchant 7: %v", err)
	}
}
