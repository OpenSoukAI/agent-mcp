package endpointpath

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

type vectors struct {
	Normalize []struct {
		In  string `json:"in"`
		Out string `json:"out"`
		Err bool   `json:"err"`
	} `json:"normalize"`
	Match []struct {
		Registered string `json:"registered"`
		Requested  string `json:"requested"`
		Want       bool   `json:"want"`
	} `json:"match"`
	Concrete []struct {
		In     string `json:"in"`
		Sample string `json:"sample"`
		Out    string `json:"out"`
		Err    bool   `json:"err"`
	} `json:"concrete"`
	Template []struct {
		In string `json:"in"`
		OK bool   `json:"ok"`
	} `json:"template"`
	Conflict []struct {
		A    string `json:"a"`
		B    string `json:"b"`
		Want bool   `json:"want"`
	} `json:"conflict"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func TestNormalize_Vectors(t *testing.T) {
	for _, c := range loadVectors(t).Normalize {
		t.Run(c.In, func(t *testing.T) {
			got, err := Normalize(c.In)
			if c.Err {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Normalize(%q) = %q, %v; want ErrInvalid", c.In, got, err)
				}
				return
			}
			if err != nil || got != c.Out {
				t.Fatalf("Normalize(%q) = %q, %v; want %q", c.In, got, err, c.Out)
			}
		})
	}
}

func TestMatches_Vectors(t *testing.T) {
	for _, c := range loadVectors(t).Match {
		t.Run(c.Registered+" vs "+c.Requested, func(t *testing.T) {
			if got := Matches(c.Registered, c.Requested); got != c.Want {
				t.Fatalf("Matches(%q, %q) = %v; want %v", c.Registered, c.Requested, got, c.Want)
			}
		})
	}
}

func TestConflicts_Vectors(t *testing.T) {
	for _, c := range loadVectors(t).Conflict {
		t.Run(c.A+" vs "+c.B, func(t *testing.T) {
			if got := Conflicts(c.A, c.B); got != c.Want {
				t.Fatalf("Conflicts(%q, %q) = %v; want %v", c.A, c.B, got, c.Want)
			}
			if got := Conflicts(c.B, c.A); got != c.Want {
				t.Fatalf("Conflicts(%q, %q) = %v; want %v (swapped)", c.B, c.A, got, c.Want)
			}
		})
	}
}

func TestResolve_FixedWinsOverTemplate(t *testing.T) {
	i, err := Resolve([]string{"/rpc/{network}", "/rpc/base"}, "/rpc/base")
	if err != nil || i != 1 {
		t.Fatalf("Resolve = %d, %v; want 1, nil", i, err)
	}
}

func TestResolve_SingleTemplate(t *testing.T) {
	i, err := Resolve([]string{"/rpc/{network}", "/rpc/base"}, "/rpc/eth")
	if err != nil || i != 0 {
		t.Fatalf("Resolve = %d, %v; want 0, nil", i, err)
	}
}

func TestResolve_NoMatch(t *testing.T) {
	if _, err := Resolve([]string{"/a"}, "/b"); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v; want ErrNoMatch", err)
	}
}

func TestResolve_DuplicateFixedIsAmbiguous(t *testing.T) {
	if _, err := Resolve([]string{"/a", "/a"}, "/a"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v; want ErrAmbiguous", err)
	}
}

func TestResolve_TwoTemplatesAmbiguous(t *testing.T) {
	if _, err := Resolve([]string{"/a/{x}", "/{y}/b"}, "/a/b"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v; want ErrAmbiguous", err)
	}
}

func TestConcrete_Vectors(t *testing.T) {
	for _, c := range loadVectors(t).Concrete {
		t.Run(c.In, func(t *testing.T) {
			got, err := Concrete(c.In, c.Sample)
			if c.Err {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("Concrete(%q) = %q, %v; want ErrInvalid", c.In, got, err)
				}
				return
			}
			if err != nil || got != c.Out {
				t.Fatalf("Concrete(%q) = %q, %v; want %q", c.In, got, err, c.Out)
			}
		})
	}
}

func TestCheckTemplate_Vectors(t *testing.T) {
	for _, c := range loadVectors(t).Template {
		t.Run(c.In, func(t *testing.T) {
			err := CheckTemplate(c.In)
			if c.OK && err != nil {
				t.Fatalf("CheckTemplate(%q) = %v; want nil", c.In, err)
			}
			if !c.OK && !errors.Is(err, ErrPartialTemplate) {
				t.Fatalf("CheckTemplate(%q) = %v; want ErrPartialTemplate", c.In, err)
			}
		})
	}
}
