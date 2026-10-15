package main

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// domainSpec is the one EIP-712 domain a commitment type is valid in. Values mirror the
// backend's internal/signing builders; the contract is resolved per chain at call time.
type domainSpec struct {
	primary  string
	name     string
	version  string
	contract protocolKey
}

var (
	specReview       = domainSpec{"ReviewCommitment", "ReviewRegistry", "1", keyReviewRegistry}
	specVote         = domainSpec{"VoteCommitment", "ReferrerVotes", "1", keyReviewRegistry}
	specCashbackRate = domainSpec{"CashbackRateCommitment", "ReferrerCashbackRate", "1", keyReviewRegistry}
	specIntentAccess = domainSpec{"IntentAccessCommitment", "ReferrerIntentAccess", "1", keyReviewRegistry}
	specIntentMark   = domainSpec{"IntentMarkCommitment", "ReferrerIntentAccess", "1", keyReviewRegistry}
	specIntentSkip   = domainSpec{"IntentSkipCommitment", "ReferrerIntentAccess", "1", keyReviewRegistry}
	specTelegramLink = domainSpec{"TelegramLinkCommitment", "ReferrerTelegramLink", "1", keyReviewRegistry}
	specCharge       = domainSpec{"ChargeCommitment", "ReferrerMPPCharge", "1", keySplitRouter}
)

// pinDomain refuses a domain that is not this signer's chain, the commitment's fixed
// name/version, or the configured contract. Runs before any key lookup or digest.
func pinDomain(ctx context.Context, d commitmentDomain, spec domainSpec) error {
	chainID, err := configuredChainID()
	if err != nil {
		return err
	}
	if d.ChainID != chainID {
		return fmt.Errorf("%s domain chainId %d but this signer is configured for chain %d", spec.primary, d.ChainID, chainID)
	}
	if d.Name != spec.name || d.Version != spec.version {
		return fmt.Errorf("%s domain name/version %q/%q but %s uses %q/%q", spec.primary, d.Name, d.Version, spec.primary, spec.name, spec.version)
	}
	want, err := resolveAddress(ctx, chainID, spec.contract)
	if err != nil {
		return fmt.Errorf("%s domain: %w", spec.primary, err)
	}
	if common.HexToAddress(d.VerifyingContract) != want {
		return fmt.Errorf("%s domain verifyingContract %s but %s on chain %d is %s", spec.primary, d.VerifyingContract, spec.contract, chainID, want.Hex())
	}
	return nil
}
