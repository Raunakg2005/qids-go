package qids

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// pqcVectors mirrors testdata/pqc_vectors.json: real gateway receipts plus
// statements no honest gateway signs, each with the outcome to reach. The
// QIDS repository generates them (tests/vectors/make_pqc_vectors.py) and
// checks the same file with its Python verifier.
type pqcVectors struct {
	Context      string `json:"context"`
	ContextCheck struct {
		PQC          PQCReceipt `json:"pqc"`
		PublicKeyPEM string     `json:"public_key_pem"`
	} `json:"context_check"`
	Vectors []struct {
		Name         string          `json:"name"`
		PayloadB64   string          `json:"payload_b64"`
		PQC          PQCReceipt      `json:"pqc"`
		PublicKeyPEM string          `json:"public_key_pem"`
		TenantID     *string         `json:"tenant_id"`
		Expect       string          `json:"expect"`
		Reason       ReceiptReason   `json:"reason"`
		Claims       json.RawMessage `json:"claims"`
	} `json:"vectors"`
}

func loadPQCVectors(t *testing.T) pqcVectors {
	t.Helper()
	raw, err := os.ReadFile("testdata/pqc_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v pqcVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Vectors) < 30 {
		t.Fatalf("only %d vectors", len(v.Vectors))
	}
	return v
}

func TestVerifyPQCReceiptVectors(t *testing.T) {
	v := loadPQCVectors(t)
	reasons := map[ReceiptReason]bool{}
	algorithms := map[string]bool{}
	for _, vec := range v.Vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			payload, err := base64.StdEncoding.DecodeString(vec.PayloadB64)
			if err != nil {
				t.Fatal(err)
			}
			tenant := ""
			if vec.TenantID != nil {
				tenant = *vec.TenantID
			}
			claims, err := VerifyPQCReceipt(payload, vec.PQC, vec.PublicKeyPEM, tenant)
			if vec.Expect == "valid" {
				if err != nil {
					t.Fatalf("valid receipt rejected: %v", err)
				}
				var want PQCClaims
				if err := json.Unmarshal(vec.Claims, &want); err != nil {
					t.Fatal(err)
				}
				statement, _ := base64.StdEncoding.DecodeString(vec.PQC.Statement)
				want.Statement = statement
				if !reflect.DeepEqual(*claims, want) {
					t.Fatalf("claims\n got %+v\nwant %+v", *claims, want)
				}
				algorithms[claims.Algorithm] = true
				return
			}
			var re *ReceiptError
			if !errors.As(err, &re) || !errors.Is(err, ErrInvalidReceipt) {
				t.Fatalf("want a *ReceiptError (%s), got %v", vec.Reason, err)
			}
			if re.Reason != vec.Reason {
				t.Fatalf("reason %s, want %s (%v)", re.Reason, vec.Reason, err)
			}
			if claims != nil {
				t.Fatalf("claims returned with an error: %+v", claims)
			}
			reasons[re.Reason] = true
		})
	}
	for _, r := range []ReceiptReason{ReasonInvalidKey, ReasonMalformedReceipt, ReasonBadSignature,
		ReasonKeyMismatch, ReasonAlgorithmMismatch, ReasonDocumentMismatch, ReasonTenantMismatch} {
		if !reasons[r] {
			t.Errorf("no vector exercised %s", r)
		}
	}
	for _, a := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		if !algorithms[a] {
			t.Errorf("no valid %s receipt", a)
		}
	}
}

// The gateway's signature verifies only under the qids-receipt-v1 context:
// checked with circl directly, without and with it.
func TestGatewaySignatureNeedsTheContext(t *testing.T) {
	v := loadPQCVectors(t)
	if v.Context != PQCContext {
		t.Fatalf("vectors use context %q, the SDK %q", v.Context, PQCContext)
	}
	_, scheme, pk, _, err := parsePQCPublicKey(v.ContextCheck.PublicKeyPEM)
	if err != nil || scheme.Name() != "ML-DSA-65" {
		t.Fatalf("%v %v", scheme, err)
	}
	statement, _ := base64.StdEncoding.DecodeString(v.ContextCheck.PQC.Statement)
	sig, _ := base64.StdEncoding.DecodeString(v.ContextCheck.PQC.Signature)
	key := pk.(*mldsa65.PublicKey)
	if mldsa65.Verify(key, statement, nil, sig) {
		t.Fatal("the gateway's signature verified with no context")
	}
	if !mldsa65.Verify(key, statement, []byte(PQCContext), sig) {
		t.Fatal("the gateway's signature did not verify with the qids-receipt-v1 context")
	}
}

func TestGetPQCKeys(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		if strings.HasSuffix(r.URL.Path, "/nobody") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"No signing keys for this tenant"}`))
			return
		}
		_, _ = w.Write([]byte(`{"tenant_id":"t/1","context":"qids-receipt-v1","keys":[` +
			`{"key_id":"k2","algorithm":"ML-DSA-65","status":"active","public_key_pem":"PEM2","created_at":2.5,"retired_at":null},` +
			`{"key_id":"k1","algorithm":"ML-DSA-65","status":"retired","public_key_pem":"PEM1","created_at":1,"retired_at":2.5}]}`))
	}))
	defer srv.Close()

	// No API key needed: the keys are public.
	keys, err := NewQIDSClient(srv.URL, "verifier").GetPQCKeys("t/1")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/v1/pqc/keys/t%2F1" || gotAuth != "" {
		t.Fatalf("path %q auth %q", gotPath, gotAuth)
	}
	if len(keys) != 2 || keys[0].Status != "active" || keys[0].PublicKeyPEM != "PEM2" ||
		keys[0].RetiredAt != nil || keys[1].RetiredAt == nil || *keys[1].RetiredAt != 2.5 {
		t.Fatalf("keys %+v", keys)
	}

	_, err = NewQIDSClientWithKey(srv.URL, "verifier", "sk_test_x").GetPQCKeys("nobody")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 || gotAuth != "Bearer sk_test_x" {
		t.Fatalf("want a 404 *APIError, got %v (auth %q)", err, gotAuth)
	}
}

func TestSignReturnsThePQCReceipt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"document_id":"d1","signature_tags":[],"pqc":{"algorithm":"ML-DSA-65",` +
			`"key_id":"abc","statement":"e30=","signature":"AAAA"}}`))
	}))
	defer srv.Close()
	res, err := NewQIDSClientWithKey(srv.URL, "SAE_Alice", "sk_test_x").Sign("d1", []byte("x"), []string{"SAE_Bob"})
	if err != nil {
		t.Fatal(err)
	}
	if res.PQC == nil || *res.PQC != (PQCReceipt{"ML-DSA-65", "abc", "e30=", "AAAA"}) {
		t.Fatalf("pqc %+v", res.PQC)
	}
}

// TestPQCAgainstRealGateway signs on a running gateway, fetches the tenant's
// published key once, then verifies the receipt offline.
// Set QIDS_TEST_GATEWAY_URL and QIDS_TEST_API_KEY to a running gateway.
func TestPQCAgainstRealGateway(t *testing.T) {
	url, key := os.Getenv("QIDS_TEST_GATEWAY_URL"), os.Getenv("QIDS_TEST_API_KEY")
	if url == "" || key == "" {
		t.Skip("QIDS_TEST_GATEWAY_URL / QIDS_TEST_API_KEY not set")
	}
	c := NewQIDSClientWithKey(url, "SAE_Alice", key)
	docID := "go-pqc-" + base64.RawURLEncoding.EncodeToString([]byte(t.Name()+os.Getenv("QIDS_TEST_NONCE")))
	sig, err := c.Sign(docID, binaryDoc, []string{"SAE_Bob"})
	if err != nil {
		t.Fatal(err)
	}
	if sig.PQC == nil {
		t.Fatal("the gateway returned no pqc receipt")
	}
	// A test may read the tenant from the statement; a real verifier knows
	// whose receipt it expects and pins that tenant's key.
	statement, _ := base64.StdEncoding.DecodeString(sig.PQC.Statement)
	var unverified struct {
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(statement, &unverified); err != nil {
		t.Fatal(err)
	}
	keys, err := NewQIDSClient(url, "verifier").GetPQCKeys(unverified.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	var pemKey string
	for _, k := range keys {
		if k.KeyID == sig.PQC.KeyID {
			pemKey = k.PublicKeyPEM
		}
	}
	if pemKey == "" {
		t.Fatalf("key %s is not among the tenant's published keys %+v", sig.PQC.KeyID, keys)
	}

	claims, err := VerifyPQCReceipt(binaryDoc, *sig.PQC, pemKey, unverified.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DocumentID != docID || claims.DocumentHash != sig.DocumentHash ||
		!reflect.DeepEqual(claims.Recipients, []string{"SAE_Bob"}) {
		t.Fatalf("claims %+v", claims)
	}
	other := append([]byte{0xfe}, binaryDoc[1:]...)
	if _, err := VerifyPQCReceipt(other, *sig.PQC, pemKey, ""); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("a different document was accepted: %v", err)
	}
	if !bytes.Equal(claims.Statement, statement) {
		t.Fatal("claims.Statement is not the signed bytes")
	}
}
