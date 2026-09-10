package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── Authenticated backend calls ─────────────────────────────────────────────────
//
// The merchant tools that write to the backend rather than the chain all do the same
// thing: sign the request with the merchant's key (see agentauth.go) and turn a status
// code into something an agent can act on.
//
// Nothing here retries. Every retry must re-sign — the backend rejects a repeat of the
// same (signer, payload hash) — and a write that may or may not have landed is the
// agent's decision to repeat, not ours. The mapped errors say which failures are worth
// retrying.
//
// Validation is NOT mirrored from the backend. Description length, URL scheme and the
// rest are enforced there and returned as a 400 with a message, which these tools pass
// through verbatim. A second copy of those bounds here would be a second thing to keep in
// sync, and the copy that drifts is the one that rejects a request the backend would
// have accepted.

// restTimeout bounds one backend call. Generous, because check_product_readiness probes a
// third-party merchant endpoint behind an 8s server-side timeout before answering.
const restTimeout = 30 * time.Second

// apiBaseURL reads the backend's base URL, trimming a trailing slash so path joining is
// unambiguous.
func apiBaseURL() (string, error) {
	raw := strings.TrimSpace(os.Getenv("REFERRER_API_URL"))
	if raw == "" {
		return "", fmt.Errorf("REFERRER_API_URL env var not set (the backend base URL, e.g. http://localhost:8080)")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

// merchantIDForREST narrows the id to the int64 the backend's JSON uses. Chain calls take
// a *big.Int, so the two paths disagree on width and a merchant id that fits one and not
// the other has to fail with the reason named rather than silently wrapping.
func merchantIDForREST(id *big.Int) (int64, error) {
	if !id.IsInt64() {
		return 0, fmt.Errorf("merchant_id %s is too large for the backend API (int64)", id)
	}
	return id.Int64(), nil
}

// backendError is the shape every backend error response uses.
type backendError struct {
	Error string `json:"error"`
}

// callAuthedRaw signs and sends one request and returns the 200 response body.
//
// tool and advice shape the failure text: advice[status] supplies the per-endpoint
// explanation for a status whose generic meaning is not enough on its own.
func callAuthedRaw(
	ctx context.Context,
	tool, method, path string,
	body []byte,
	merchantID *big.Int,
	advice map[int]string,
) ([]byte, error) {
	privKey, err := signerKeys.KeyFor(merchantID.String())
	if err != nil {
		return nil, err
	}

	base, err := apiBaseURL()
	if err != nil {
		return nil, err
	}

	req, err := newAuthedRequest(ctx, method, base+path, body, privKey)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: restTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %s %s: %w", tool, method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: read response: %w", tool, err)
	}

	// Any 2xx is success. The register endpoints answer 201, not 200, and a client that
	// insisted on 200 would treat every successful registration as a failure.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, restError(tool, resp.StatusCode, raw, advice)
	}
	return raw, nil
}

// callAuthedJSON decodes the response into a generic object, for the endpoints whose reply
// is read field by field.
func callAuthedJSON(
	ctx context.Context,
	tool, method, path string,
	body []byte,
	merchantID *big.Int,
	advice map[int]string,
) (map[string]any, error) {
	raw, err := callAuthedRaw(ctx, tool, method, path, body, merchantID, advice)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s: the backend returned a body that is not a JSON object: %s",
			tool, truncate(string(raw), 200))
	}
	return out, nil
}

// callAuthedInto decodes the response into a typed destination. Used where the reply
// carries integers: encoding/json turns every number in a map[string]any into a float64,
// which silently rounds an int64 above 2^53 — and revenue is an int64 of USDC base units.
func callAuthedInto(
	ctx context.Context,
	tool, method, path string,
	body []byte,
	merchantID *big.Int,
	advice map[int]string,
	dest any,
) error {
	raw, err := callAuthedRaw(ctx, tool, method, path, body, merchantID, advice)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return fmt.Errorf("%s: cannot decode the backend's response: %w (body: %s)",
			tool, err, truncate(string(raw), 200))
	}
	return nil
}

// restStatusError is a non-2xx response. It carries the status as a FIELD rather than only
// in the message, because the composites have to act on it: a 409 "already registered" is a
// successful outcome for a step that is being re-run, and matching that on error text would
// break the first time the backend rewords it.
type restStatusError struct {
	Tool   string
	Status int
	Detail string // the backend's own message where it gave one
	Advice string
}

func (e *restStatusError) Error() string {
	if e.Advice != "" {
		return fmt.Sprintf("%s failed (%d): %s — %s", e.Tool, e.Status, e.Detail, e.Advice)
	}
	return fmt.Sprintf("%s failed (%d): %s", e.Tool, e.Status, e.Detail)
}

// restStatus returns the HTTP status behind err, or 0 if err is not a status error.
func restStatus(err error) int {
	var se *restStatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// restError builds the caller-facing error for a non-2xx. The backend's own message is
// always included — it is more specific than anything derivable from the status — and the
// per-status advice explains what to do about it.
func restError(tool string, status int, raw []byte, advice map[int]string) error {
	var be backendError
	_ = json.Unmarshal(raw, &be)

	detail := be.Error
	if detail == "" {
		detail = truncate(strings.TrimSpace(string(raw)), 200)
	}
	if detail == "" {
		detail = "(no message)"
	}

	msg, ok := advice[status]
	if !ok {
		msg = genericRESTAdvice[status]
	}
	return &restStatusError{Tool: tool, Status: status, Detail: detail, Advice: msg}
}

// genericRESTAdvice covers the statuses that mean the same thing on every authenticated
// endpoint. 401 is the one worth spelling out: the signature is computed over the exact
// request body and a unix timestamp the server checks to ±60s, so a wrong key, a clock
// more than a minute out, and a resent request all land here and need different fixes.
var genericRESTAdvice = map[int]string{
	http.StatusUnauthorized:    "the request signature was rejected: check that AGENT_KEYS holds the key for this merchant_id, that this machine's clock is within 60s of the server's, and that this is not a resend of an already-accepted request (each attempt must be signed afresh)",
	http.StatusForbidden:       "the signing key does not own this merchant identity",
	http.StatusNotFound:        "no such merchant on-chain for this chain's IdentityRegistry",
	http.StatusTooManyRequests: "rate limited — wait and call again",
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
