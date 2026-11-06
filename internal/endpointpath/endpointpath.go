// Copied from OpenSoukAI/backend internal/endpointpath at dev b2c8715: the rule the
// facilitator settles by. Keep testdata/vectors.json byte-identical to the backend's.

// Package endpointpath is the rule that maps a URL a merchant served to the product registered
// at that path. Only the path is compared: host, scheme, port and query are dropped,
// because a merchant behind a proxy sees an internal host and the query holds the buyer's input.
// A registered segment written {name} or :name matches any one segment.
package endpointpath

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

var (
	ErrInvalid   = errors.New("endpoint must be an http(s) URL or a path starting with /")
	ErrNoMatch   = errors.New("no registered endpoint matches")
	ErrAmbiguous = errors.New("several registered endpoints match")
	// ErrPartialTemplate's text is shown to merchants as is.
	ErrPartialTemplate = errors.New("a template parameter must be a whole path segment, like /files/{id}; a brace inside a segment, like file-{id}.json, is not supported")
)

var (
	braceParam = regexp.MustCompile(`^\{[^/{}]+\}$`)
	colonParam = regexp.MustCompile(`^:[A-Za-z_][A-Za-z0-9_]*$`)
)

// splitRaw cuts raw into prefix (scheme and authority, "" for a bare path), the escaped path,
// and suffix (query and fragment), byte-for-byte. The path is cut from the raw string rather than
// taken from url.URL: EscapedPath re-encodes u.Path when the original has characters Go deems
// invalid, and an encoded slash then comes back as a real one.
func splitRaw(raw string) (prefix, path, suffix string, err error) {
	if strings.HasPrefix(raw, "/") {
		// Parsed by hand: url.Parse would read "//x/a" as host x.
		i := strings.IndexAny(raw, "?#")
		if i < 0 {
			return "", raw, "", nil
		}
		return "", raw[:i], raw[i:], nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", "", "", ErrInvalid
	}
	start := strings.Index(raw, "//") + 2
	rest := raw[start:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		return raw, "", "", nil
	}
	prefix = raw[:start+end]
	if rest[end] != '/' {
		return prefix, "", rest[end:], nil
	}
	tail := rest[end:]
	if i := strings.IndexAny(tail, "?#"); i >= 0 {
		return prefix, tail[:i], tail[i:], nil
	}
	return prefix, tail, "", nil
}

// Normalize returns the path of a full http(s) URL or of a path starting with "/", without query,
// fragment or trailing slash ("/" for the root). Each segment is decoded on its own after the
// split, so an encoded slash cannot create a segment the merchant's router never saw; a segment
// that decodes to "/", "." or ".." is refused.
func Normalize(raw string) (string, error) {
	_, escaped, _, err := splitRaw(raw)
	if err != nil {
		return "", err
	}
	escaped = strings.TrimRight(escaped, "/")
	if escaped == "" {
		return "/", nil
	}
	segs := strings.Split(escaped, "/")
	for i, seg := range segs {
		dec, err := url.PathUnescape(seg)
		if err != nil || strings.Contains(dec, "/") || dec == "." || dec == ".." {
			return "", ErrInvalid
		}
		segs[i] = dec
	}
	return strings.Join(segs, "/"), nil
}

// CheckTemplate refuses a normalised registered path with a brace outside a whole {name}
// segment. Matching treats such a segment literally, so no request could ever resolve to it.
func CheckTemplate(path string) error {
	for _, s := range segments(path) {
		if !isParam(s) && strings.ContainsAny(s, "{}") {
			return ErrPartialTemplate
		}
	}
	return nil
}

// Concrete returns the full http(s) URL raw with every template parameter segment replaced by
// sample, so a templated endpoint can be probed. Everything else is kept byte-for-byte.
func Concrete(raw, sample string) (string, error) {
	if strings.HasPrefix(raw, "/") {
		return "", ErrInvalid
	}
	prefix, path, suffix, err := splitRaw(raw)
	if err != nil {
		return "", err
	}
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if isParam(seg) {
			segs[i] = sample
		}
	}
	return prefix + strings.Join(segs, "/") + suffix, nil
}

func isParam(seg string) bool { return braceParam.MatchString(seg) || colonParam.MatchString(seg) }

func segments(path string) []string { return strings.Split(path, "/") }

// IsTemplate reports whether any segment of a normalised path is a {name} or :name parameter.
func IsTemplate(path string) bool {
	for _, s := range segments(path) {
		if isParam(s) {
			return true
		}
	}
	return false
}

// Matches reports whether a normalised registered path (which may be a template) matches a
// normalised requested path.
func Matches(registered, requested string) bool {
	r, q := segments(registered), segments(requested)
	if len(r) != len(q) {
		return false
	}
	for i := range r {
		if isParam(r[i]) {
			if q[i] == "" {
				return false
			}
		} else if r[i] != q[i] {
			return false
		}
	}
	return true
}

// Conflicts reports whether two normalised registered paths cannot both belong to one merchant:
// they are equal, or both are templates that some request would match. A fixed path beside a
// template is allowed, because the fixed one wins.
func Conflicts(a, b string) bool {
	if a == b {
		return true
	}
	if !IsTemplate(a) || !IsTemplate(b) {
		return false
	}
	x, y := segments(a), segments(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if !isParam(x[i]) && !isParam(y[i]) && x[i] != y[i] {
			return false
		}
	}
	return true
}

// Resolve returns the index in registered (normalised paths) of the path that serves requested:
// the equal fixed path, else the only matching template.
func Resolve(registered []string, requested string) (int, error) {
	fixed, tmpl := -1, -1
	nFixed, nTmpl := 0, 0
	for i, p := range registered {
		if IsTemplate(p) {
			if Matches(p, requested) {
				tmpl = i
				nTmpl++
			}
		} else if p == requested {
			fixed = i
			nFixed++
		}
	}
	switch {
	case nFixed == 1:
		return fixed, nil
	case nFixed > 1:
		return -1, ErrAmbiguous
	case nTmpl == 1:
		return tmpl, nil
	case nTmpl > 1:
		return -1, ErrAmbiguous
	}
	return -1, ErrNoMatch
}
