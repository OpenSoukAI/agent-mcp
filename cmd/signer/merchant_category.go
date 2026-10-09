package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// checkCategory refuses a category outside the backend's vocabulary before add_product writes
// the product on-chain: the backend refuses it too (REF-447), but only in the metadata sync,
// after addProduct has spent the gas and left a payable product nobody can discover. The
// vocabulary is read from the backend itself, so there is no second copy to drift.
func checkCategory(ctx context.Context, category string) error {
	if category == "" {
		return nil
	}
	base, err := apiBaseURL()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/product-categories", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: restTimeout}).Do(req)
	if err != nil {
		return fmt.Errorf("could not check category %q against GET /v1/product-categories, so nothing was sent: %w", category, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not check category %q against GET /v1/product-categories (status %d), so nothing was sent", category, resp.StatusCode)
	}
	var vocab struct {
		Categories []struct {
			Slug string `json:"slug"`
		} `json:"categories"`
	}
	if err := json.Unmarshal(raw, &vocab); err != nil {
		return fmt.Errorf("could not read GET /v1/product-categories, so nothing was sent: %w", err)
	}
	var examples []string
	for _, c := range vocab.Categories {
		if c.Slug == category {
			return nil
		}
		if len(examples) < 3 {
			examples = append(examples, c.Slug)
		}
	}
	return fmt.Errorf("category %q is not in the product category vocabulary, and the backend would refuse it "+
		"after addProduct had spent the gas; nothing was sent. Pick a slug from GET /v1/product-categories, "+
		"e.g. %s", category, strings.Join(examples, ", "))
}
