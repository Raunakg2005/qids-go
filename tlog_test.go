package qids

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"testing"
	"time"
)

// tlogVectors mirrors testdata/tlog_vectors.json: signed tree heads,
// inclusion and consistency proofs from a real gateway, and edits of them,
// each with the outcome to reach. The QIDS repository generates them
// (tests/vectors/make_tlog_vectors.py) and checks the same file with its
// Python verifiers.
type tlogVectors struct {
	Context  string `json:"context"`
	Receipts []struct {
		PQC      PQCReceipt `json:"pqc"`
		LeafHash string     `json:"leaf_hash"`
		Index    uint64     `json:"index"`
	} `json:"receipts"`
	TreeHeads []struct {
		Name         string                     `json:"name"`
		STH          SignedTreeHead             `json:"sth"`
		PublicKeyPEM string                     `json:"public_key_pem"`
		TenantID     *string                    `json:"tenant_id"`
		Expect       string                     `json:"expect"`
		Reason       TlogReason                 `json:"reason"`
		Claims       map[string]json.RawMessage `json:"claims"`
	} `json:"tree_heads"`
	Inclusion []struct {
		Name      string     `json:"name"`
		LeafHash  string     `json:"leaf_hash"`
		Index     uint64     `json:"index"`
		TreeSize  uint64     `json:"tree_size"`
		AuditPath []string   `json:"audit_path"`
		RootHash  string     `json:"root_hash"`
		Expect    string     `json:"expect"`
		Reason    TlogReason `json:"reason"`
	} `json:"inclusion"`
	Consistency []struct {
		Name       string     `json:"name"`
		FirstSize  uint64     `json:"first_size"`
		SecondSize uint64     `json:"second_size"`
		FirstRoot  string     `json:"first_root"`
		SecondRoot string     `json:"second_root"`
		Proof      []string   `json:"proof"`
		Expect     string     `json:"expect"`
		Reason     TlogReason `json:"reason"`
	} `json:"consistency"`
}

func loadTlogVectors(t *testing.T) tlogVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/tlog_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v tlogVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustHashes(t *testing.T, hs []string) [][]byte {
	t.Helper()
	b, err := DecodeHashes(hs)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func wantTlogReason(t *testing.T, err error, reason TlogReason) {
	t.Helper()
	var te *TlogError
	if !errors.As(err, &te) || !errors.Is(err, ErrInvalidTlog) {
		t.Fatalf("want a *TlogError (%s), got %v", reason, err)
	}
	if te.Reason != reason {
		t.Fatalf("reason %s, want %s: %v", te.Reason, reason, err)
	}
}

func TestTlogVectorsCoverEveryReason(t *testing.T) {
	v := loadTlogVectors(t)
	if v.Context != TlogContext {
		t.Fatalf("context %q, want %q", v.Context, TlogContext)
	}
	seen := map[string]bool{}
	for _, h := range v.TreeHeads {
		if h.Expect == "error" {
			seen[string(h.Reason)] = true
		}
	}
	for _, p := range v.Inclusion {
		if p.Expect == "error" {
			seen[string(p.Reason)] = true
		}
	}
	for _, c := range v.Consistency {
		if c.Expect == "error" {
			seen[string(c.Reason)] = true
		}
	}
	var got []string
	for r := range seen {
		got = append(got, r)
	}
	sort.Strings(got)
	want := []string{"bad_signature", "bad_sizes", "empty_proof", "fork", "inconsistent", "index_out_of_range",
		"invalid_key", "key_mismatch", "malformed_tree_head", "proof_too_long", "root_mismatch", "tenant_mismatch"}
	if len(got) != len(want) {
		t.Fatalf("reasons %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reasons %v, want %v", got, want)
		}
	}
}

func TestTreeHeadVectors(t *testing.T) {
	for _, v := range loadTlogVectors(t).TreeHeads {
		t.Run(v.Name, func(t *testing.T) {
			tenant := ""
			if v.TenantID != nil {
				tenant = *v.TenantID
			}
			claims, err := VerifyTreeHead(v.STH, v.PublicKeyPEM, tenant)
			if v.Expect == "error" {
				wantTlogReason(t, err, v.Reason)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var size uint64
			var root, tenantID string
			json.Unmarshal(v.Claims["tree_size"], &size)
			json.Unmarshal(v.Claims["root_hash"], &root)
			json.Unmarshal(v.Claims["tenant_id"], &tenantID)
			if claims.TreeSize != size || claims.RootHash != root || claims.TenantID != tenantID ||
				claims.Type != "qids-sth" {
				t.Fatalf("claims %+v, want size %d root %s tenant %s", claims, size, root, tenantID)
			}
			statement, _ := base64.StdEncoding.DecodeString(v.STH.Statement)
			if string(claims.Statement) != string(statement) {
				t.Fatal("Statement is not the signed bytes")
			}
		})
	}
}

func TestInclusionVectors(t *testing.T) {
	for _, v := range loadTlogVectors(t).Inclusion {
		t.Run(v.Name, func(t *testing.T) {
			err := VerifyInclusion(mustHex(t, v.LeafHash), v.Index, v.TreeSize, mustHashes(t, v.AuditPath),
				mustHex(t, v.RootHash))
			if v.Expect == "error" {
				wantTlogReason(t, err, v.Reason)
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConsistencyVectors(t *testing.T) {
	for _, v := range loadTlogVectors(t).Consistency {
		t.Run(v.Name, func(t *testing.T) {
			err := VerifyConsistency(v.FirstSize, v.SecondSize, mustHex(t, v.FirstRoot), mustHex(t, v.SecondRoot),
				mustHashes(t, v.Proof))
			if v.Expect == "error" {
				wantTlogReason(t, err, v.Reason)
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReceiptLeafHashVectors(t *testing.T) {
	for _, r := range loadTlogVectors(t).Receipts {
		got, err := ReceiptLeafHash(r.PQC)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != r.LeafHash {
			t.Fatalf("leaf hash %x, want %s", got, r.LeafHash)
		}
	}
	if _, err := ReceiptLeafHash(PQCReceipt{Statement: "%%%"}); err == nil {
		t.Fatal("a statement that is not base64 has no leaf hash")
	}
}

// TestTlogAgainstRealGateway signs on a running gateway and proves the
// receipt is in its tenant's log, checking the tree head offline.
// Set QIDS_TEST_GATEWAY_URL and QIDS_TEST_API_KEY to a running gateway.
func TestTlogAgainstRealGateway(t *testing.T) {
	url, key := os.Getenv("QIDS_TEST_GATEWAY_URL"), os.Getenv("QIDS_TEST_API_KEY")
	if url == "" || key == "" {
		t.Skip("QIDS_TEST_GATEWAY_URL / QIDS_TEST_API_KEY not set")
	}
	c := NewQIDSClientWithKey(url, "SAE_Alice", key)
	sig, err := c.Sign("go-tlog-"+time.Now().Format("150405.000000"), []byte("a document for the log"), []string{"SAE_Bob"})
	if err != nil {
		t.Fatal(err)
	}
	statement, _ := base64.StdEncoding.DecodeString(sig.PQC.Statement)
	var unverified struct {
		TenantID string `json:"tenant_id"`
	}
	json.Unmarshal(statement, &unverified)
	reader := NewQIDSClient(url, "monitor")
	keys, err := reader.GetPQCKeys(unverified.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	sth, err := reader.GetTreeHead(unverified.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	head, err := VerifyTreeHead(*sth, keys[0].PublicKeyPEM, unverified.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := ReceiptLeafHash(*sig.PQC)
	proof, err := reader.GetInclusionProof(unverified.TenantID, leaf, head.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := DecodeHashes(proof.AuditPath)
	root, _ := hex.DecodeString(head.RootHash)
	if err := VerifyInclusion(leaf, proof.Index, head.TreeSize, path, root); err != nil {
		t.Fatal(err)
	}
}
