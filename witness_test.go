package qids

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

// witnessVectors mirrors testdata/witness_vectors.json: a real gateway's GET
// /api/v1/tlog/<tenant>/cosigned, co-signed by real qids.witness witnesses,
// and edits of it, each with the outcome to reach. The QIDS repository
// generates them (tests/vectors/make_witness_vectors.py) and holds its Python
// verifier and the TypeScript SDK to the same outcomes.
type witnessVectors struct {
	WitnessContext string            `json:"witness_context"`
	Keys           map[string]string `json:"keys"`
	WitnessKids    map[string]string `json:"witness_kids"`
	Cosigned       []struct {
		Name         string            `json:"name"`
		Cosigned     CosignedTreeHeads `json:"cosigned"`
		LogKey       string            `json:"log_key"`
		Trusted      []string          `json:"trusted"`
		Quorum       int               `json:"quorum"`
		TenantID     *string           `json:"tenant_id"`
		Expect       string            `json:"expect"`
		Reason       TlogReason        `json:"reason"`
		TreeSize     uint64            `json:"tree_size"`
		Witnesses    []string          `json:"witnesses"`
		CosignedAtMs int64             `json:"cosigned_at_ms"`
	} `json:"cosigned"`
}

func loadWitnessVectors(t *testing.T) *witnessVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/witness_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v witnessVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func TestWitnessVectors(t *testing.T) {
	v := loadWitnessVectors(t)
	if v.WitnessContext != WitnessContext {
		t.Fatalf("context %q, vectors %q", WitnessContext, v.WitnessContext)
	}
	reasons, sizes := map[TlogReason]bool{}, map[uint64]bool{}
	for _, c := range v.Cosigned {
		t.Run(c.Name, func(t *testing.T) {
			trusted := make([]string, len(c.Trusted))
			for i, k := range c.Trusted {
				trusted[i] = v.Keys[k]
			}
			tenant := ""
			if c.TenantID != nil {
				tenant = *c.TenantID
			}
			got, err := VerifyCosignedTreeHead(c.Cosigned, v.Keys[c.LogKey], trusted, c.Quorum, tenant)
			if c.Expect == "valid" {
				sizes[c.TreeSize] = true
				if err != nil {
					t.Fatal(err)
				}
				if got.TreeSize != c.TreeSize || !reflect.DeepEqual(got.Witnesses, c.Witnesses) ||
					got.CosignedAtMs != c.CosignedAtMs || got.Algorithm != "ML-DSA-65" {
					t.Fatalf("got size %d witnesses %v at %d", got.TreeSize, got.Witnesses, got.CosignedAtMs)
				}
				return
			}
			reasons[c.Reason] = true
			wantTlogReason(t, err, c.Reason)
		})
	}
	want := map[TlogReason]bool{TlogInvalidKey: true, TlogWitnessIsLogKey: true, TlogQuorumNotMet: true}
	if !reflect.DeepEqual(reasons, want) || !reflect.DeepEqual(sizes, map[uint64]bool{3: true, 5: true}) {
		t.Fatalf("vectors cover reasons %v and sizes %v", reasons, sizes)
	}
}

// fullHead is the smaller head of the vectors, co-signed by all three witnesses.
func fullHead(t *testing.T, v *witnessVectors) (CosignedHead, *TreeHeadClaims) {
	t.Helper()
	for _, c := range v.Cosigned {
		if c.Name == "a quorum of 3" {
			head := c.Cosigned.Heads[1]
			claims, err := VerifyTreeHead(head.STH, v.Keys["log_a"], "")
			if err != nil {
				t.Fatal(err)
			}
			return head, claims
		}
	}
	t.Fatal("no vector named 'a quorum of 3'")
	return CosignedHead{}, nil
}

func cosigBy(v *witnessVectors, head CosignedHead, name string) Cosignature {
	for _, c := range head.Cosignatures {
		if c.Witness == v.WitnessKids[name] {
			return c
		}
	}
	return Cosignature{}
}

func TestVerifyCosignature(t *testing.T) {
	v := loadWitnessVectors(t)
	head, claims := fullHead(t, v)
	got, err := VerifyCosignature(cosigBy(v, head, "w2"), v.Keys["w2"], claims)
	if err != nil {
		t.Fatal(err)
	}
	if got.Witness != v.WitnessKids["w2"] || got.TreeSize != claims.TreeSize || got.RootHash != claims.RootHash ||
		got.LogKeyID != claims.KeyID || got.CosignedAtMs <= 0 {
		t.Fatalf("claims %+v", got)
	}

	_, err = VerifyCosignature(cosigBy(v, head, "w2"), v.Keys["w3"], claims)
	wantTlogReason(t, err, TlogBadCosignature)
	larger := *claims
	larger.TreeSize++
	_, err = VerifyCosignature(cosigBy(v, head, "w2"), v.Keys["w2"], &larger)
	wantTlogReason(t, err, TlogCosignatureMismatch)
	otherLog := *claims
	otherLog.KeyID = "00000000000000000000000000000000"
	_, err = VerifyCosignature(cosigBy(v, head, "w2"), v.Keys["w2"], &otherLog)
	wantTlogReason(t, err, TlogCosignatureMismatch)
	garbled := cosigBy(v, head, "w2")
	garbled.Statement = "not base64!"
	_, err = VerifyCosignature(garbled, v.Keys["w2"], claims)
	wantTlogReason(t, err, TlogBadCosignature)
	_, err = VerifyCosignature(cosigBy(v, head, "w2"), v.Keys["ml_dsa_44"], claims)
	wantTlogReason(t, err, TlogInvalidKey)
}

func TestCosignedQuorumMustBePositive(t *testing.T) {
	v := loadWitnessVectors(t)
	for _, q := range []int{0, -1} {
		_, err := VerifyCosignedTreeHead(v.Cosigned[0].Cosigned, v.Keys["log_a"], []string{v.Keys["w1"]}, q, "")
		if err == nil || errors.Is(err, ErrInvalidTlog) {
			t.Fatalf("quorum %d: %v", q, err)
		}
	}
}

func TestGetCosignedTreeHead(t *testing.T) {
	v := loadWitnessVectors(t)
	body, _ := json.Marshal(v.Cosigned[0].Cosigned)
	var seenPath, seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath, seenAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "t", "sk_secret")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.GetCosignedTreeHead("tenant/with slash")
	if err != nil {
		t.Fatal(err)
	}
	if seenPath != "/api/v1/tlog/tenant%2Fwith%20slash/cosigned" || seenAuth != "" {
		t.Fatalf("path %q auth %q", seenPath, seenAuth)
	}
	head, err := VerifyCosignedTreeHead(*got, v.Keys["log_a"], []string{v.Keys["w1"], v.Keys["w2"], v.Keys["w3"]}, 2, "")
	if err != nil || head.TreeSize != 3 {
		t.Fatalf("head %+v, %v", head, err)
	}
}
