package main

import (
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"
)

// responseDirEnv overrides where pay_for_product saves paid response bodies.
const responseDirEnv = "SIGNER_RESPONSE_DIR"

// defaultResponseDir sits next to the default signer.env, under the user's home.
var defaultResponseDir = filepath.Join(".config", "opensouk", "responses")

func responseDir(home func() (string, error)) (string, error) {
	if dir := os.Getenv(responseDirEnv); dir != "" {
		return dir, nil
	}
	h, err := home()
	if err != nil {
		return "", fmt.Errorf("no %s and no home directory: %w", responseDirEnv, err)
	}
	return filepath.Join(h, defaultResponseDir), nil
}

// saveResponse writes the full paid body to <dir>/<chainID>-<txHash><ext> and returns the absolute
// path. The name comes from the settlement tx, never from merchant-controlled text.
func saveResponse(home func() (string, error), chainID, txHash, contentType string, body []byte) (string, error) {
	dir, err := responseDir(home)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s%s", chainID, strings.ToLower(txHash), responseExt(contentType))
	if filepath.Base(name) != name {
		return "", fmt.Errorf("unsafe response file name %q", name)
	}
	path, err := filepath.Abs(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func responseExt(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ".bin"
	}
	switch {
	case mt == "application/json" || strings.HasSuffix(mt, "+json"):
		return ".json"
	case mt == "text/csv":
		return ".csv"
	case mt == "text/html":
		return ".html"
	case strings.HasPrefix(mt, "text/"):
		return ".txt"
	}
	return ".bin"
}
