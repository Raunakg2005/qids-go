package qids

import (
	"crypto/sha256"
	"crypto/sha3"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// PQCContext is the FIPS 204 context string the gateway signs receipts under.
// A signature made without it, or under another context, does not verify.
const PQCContext = "qids-receipt-v1"

// PQCReceipt is the "pqc" object of a sign response or an audit receipt: an
// ML-DSA (FIPS 204) signature over a statement about the signed document.
type PQCReceipt struct {
	// Algorithm is "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".
	Algorithm string `json:"algorithm"`
	// KeyID is the first 32 hex characters of SHA-256 over the raw public key.
	KeyID string `json:"key_id"`
	// Statement is the base64 of the exact signed bytes (canonical JSON).
	Statement string `json:"statement"`
	// Signature is the base64 ML-DSA signature over Statement's bytes.
	Signature string `json:"signature"`
}

// PQCOTUH is the OTUH signature a receipt statement records.
type PQCOTUH struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	Signature     string `json:"signature"`
	SignatureBits int    `json:"signature_bits"`
}

// PQCClaims is what a verified receipt statement says.
type PQCClaims struct {
	Version         int      `json:"v"`
	Algorithm       string   `json:"alg"`
	KeyID           string   `json:"kid"`
	TenantID        string   `json:"tenant_id"`
	DocumentID      string   `json:"document_id"`
	DocumentHash    string   `json:"document_hash"`
	DocumentHashAlg string   `json:"document_hash_alg"`
	SignedAtMs      int64    `json:"signed_at_ms"`
	Recipients      []string `json:"recipients"`
	OTUH            PQCOTUH  `json:"otuh"`
	// EntropySource is where the one-time key came from: "CSPRNG",
	// "ETSI-GS-QKD-014" or "ETSI-GS-QKD-014-MOCK".
	EntropySource string `json:"entropy_source"`
	// KMSKeyID is the ETSI GS QKD 014 key_ID of the one-time key; nil when
	// the key came from the CSPRNG.
	KMSKeyID *string `json:"kms_key_id"`
	// Statement holds the exact signed bytes. A field this version does not
	// model, or whose type it does not expect (left at its zero value above),
	// can be read from them.
	Statement []byte `json:"-"`
}

// PQCPublicKey is one of a tenant's published ML-DSA public keys.
type PQCPublicKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	// Status is "active" or "retired". Retired keys stay published so that
	// receipts signed with them stay verifiable.
	Status       string   `json:"status"`
	PublicKeyPEM string   `json:"public_key_pem"`
	CreatedAt    float64  `json:"created_at"`
	RetiredAt    *float64 `json:"retired_at"`
}

// ErrInvalidReceipt matches every *ReceiptError with errors.Is.
var ErrInvalidReceipt = errors.New("qids: PQC receipt rejected")

// ReceiptReason says which check rejected a receipt.
type ReceiptReason string

// The reasons, in the order VerifyPQCReceipt checks them.
const (
	// ReasonInvalidKey: the key is not a PEM SPKI ML-DSA public key.
	ReasonInvalidKey ReceiptReason = "invalid_key"
	// ReasonMalformedReceipt: the statement or signature is missing or not base64.
	ReasonMalformedReceipt ReceiptReason = "malformed_receipt"
	// ReasonBadSignature: the signature does not verify under this key and
	// the qids-receipt-v1 context.
	ReasonBadSignature ReceiptReason = "bad_signature"
	// ReasonKeyMismatch: the statement names a different key id.
	ReasonKeyMismatch ReceiptReason = "key_mismatch"
	// ReasonAlgorithmMismatch: the statement names a different parameter set.
	ReasonAlgorithmMismatch ReceiptReason = "algorithm_mismatch"
	// ReasonDocumentMismatch: the receipt is for a different document, or not
	// a SHA3-256 hash of one.
	ReasonDocumentMismatch ReceiptReason = "document_mismatch"
	// ReasonTenantMismatch: the receipt belongs to a different tenant.
	ReasonTenantMismatch ReceiptReason = "tenant_mismatch"
)

// ReceiptError is a receipt that failed an offline check.
type ReceiptError struct {
	Reason ReceiptReason
	Detail string
}

func (e *ReceiptError) Error() string {
	return fmt.Sprintf("qids: PQC receipt rejected (%s): %s", e.Reason, e.Detail)
}

// Is makes errors.Is(err, ErrInvalidReceipt) match every *ReceiptError.
func (e *ReceiptError) Is(target error) bool { return target == ErrInvalidReceipt }

func reject(reason ReceiptReason, format string, args ...interface{}) error {
	return &ReceiptError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// The FIPS 204 parameter sets by their SPKI algorithm OID (NIST CSOR).
var pqcSchemes = []struct {
	name   string
	oid    asn1.ObjectIdentifier
	scheme sign.Scheme
}{
	{"ML-DSA-44", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, mldsa44.Scheme()},
	{"ML-DSA-65", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, mldsa65.Scheme()},
	{"ML-DSA-87", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, mldsa87.Scheme()},
}

type subjectPublicKeyInfo struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

// parsePQCPublicKey reads a PEM SPKI ML-DSA public key: its parameter set,
// the parsed key and its raw bytes.
func parsePQCPublicKey(publicKeyPEM string) (string, sign.Scheme, sign.PublicKey, []byte, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", nil, nil, nil, reject(ReasonInvalidKey, "not a PEM public key")
	}
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(block.Bytes, &spki)
	if err != nil || len(rest) != 0 {
		return "", nil, nil, nil, reject(ReasonInvalidKey, "not a PEM public key: bad SubjectPublicKeyInfo")
	}
	for _, s := range pqcSchemes {
		if !spki.Algorithm.Algorithm.Equal(s.oid) {
			continue
		}
		// RFC 9881: the parameters field is absent for ML-DSA.
		raw := spki.PublicKey.Bytes
		if len(spki.Algorithm.Parameters.FullBytes) != 0 || spki.PublicKey.BitLength != 8*len(raw) ||
			len(raw) != s.scheme.PublicKeySize() {
			return "", nil, nil, nil, reject(ReasonInvalidKey, "not a PEM public key: malformed %s key", s.name)
		}
		pk, err := s.scheme.UnmarshalBinaryPublicKey(raw)
		if err != nil {
			return "", nil, nil, nil, reject(ReasonInvalidKey, "not a PEM public key: %v", err)
		}
		return s.name, s.scheme, pk, raw, nil
	}
	return "", nil, nil, nil, reject(ReasonInvalidKey, "the public key is not an ML-DSA key")
}

// decodeStrictBase64 accepts standard, padded base64 and nothing else (no
// line breaks), as the reference verifier does.
func decodeStrictBase64(s string) ([]byte, bool) {
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return b, err == nil
}

// claimString reads a string claim by its exact key; ok is false when the
// claim is absent or not a string.
func claimString(claims map[string]json.RawMessage, key string) (string, bool) {
	raw, present := claims[key]
	if !present {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// VerifyPQCReceipt checks a receipt's ML-DSA signature offline and returns
// the signed claims. Nothing here contacts the gateway.
//
// payload is the document as signed. receipt is the "pqc" object of the sign
// response or audit receipt. publicKeyPEM is the tenant's key, obtained from a
// source you trust (GetPQCKeys once, then pinned), never from the response
// being checked. tenantID, when not empty, must be the receipt's tenant.
//
// The checks, in order: the signature over the statement's exact bytes under
// the qids-receipt-v1 context; that the statement names this key (its id is a
// hash of the key) and its parameter set; that the statement's document hash
// is the SHA3-256 of payload; and the tenant. A failure is a *ReceiptError
// whose Reason names the check; errors.Is(err, ErrInvalidReceipt) matches it.
func VerifyPQCReceipt(payload []byte, receipt PQCReceipt, publicKeyPEM string, tenantID string) (*PQCClaims, error) {
	algorithm, scheme, pk, raw, err := parsePQCPublicKey(publicKeyPEM)
	if err != nil {
		return nil, err
	}
	statement, ok1 := decodeStrictBase64(receipt.Statement)
	signature, ok2 := decodeStrictBase64(receipt.Signature)
	if !ok1 || !ok2 {
		return nil, reject(ReasonMalformedReceipt, "the receipt has no valid base64 statement and signature")
	}
	if !scheme.Verify(pk, statement, signature, &sign.SignatureOpts{Context: PQCContext}) {
		return nil, reject(ReasonBadSignature, "ML-DSA signature does not verify under this key")
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(statement, &fields); err != nil {
		return nil, reject(ReasonMalformedReceipt, "the signed statement is not a JSON object: %v", err)
	}
	sum := sha256.Sum256(raw)
	if kid, _ := claimString(fields, "kid"); kid != hex.EncodeToString(sum[:])[:32] {
		return nil, reject(ReasonKeyMismatch, "the statement names a different key")
	}
	if alg, _ := claimString(fields, "alg"); alg != algorithm {
		return nil, reject(ReasonAlgorithmMismatch, "the statement says %q, the key is %s", alg, algorithm)
	}
	docHash := sha3.Sum256(payload)
	hashAlg, _ := claimString(fields, "document_hash_alg")
	hash, _ := claimString(fields, "document_hash")
	if hashAlg != "SHA3-256" || hash != hex.EncodeToString(docHash[:]) {
		return nil, reject(ReasonDocumentMismatch, "the receipt is for a different document")
	}
	if tenantID != "" {
		if tenant, _ := claimString(fields, "tenant_id"); tenant != tenantID {
			return nil, reject(ReasonTenantMismatch, "the receipt belongs to a different tenant")
		}
	}

	// Every check above passed on the exact keys; a field of an unexpected
	// type (a newer gateway's) is left at its zero value, not an error.
	claims := &PQCClaims{Statement: statement}
	var typeErr *json.UnmarshalTypeError
	if err := json.Unmarshal(statement, claims); err != nil && !errors.As(err, &typeErr) {
		return nil, reject(ReasonMalformedReceipt, "the signed statement is not a JSON object: %v", err)
	}
	return claims, nil
}

// GetPQCKeys fetches a tenant's ML-DSA public keys (active first, then
// retired) from the gateway. The endpoint is public: no API key is needed,
// and the client's key is sent only if it has one.
//
// Fetch once and pin the key you trust; VerifyPQCReceipt should not be given
// a key fetched alongside each receipt.
func (c *QIDSClient) GetPQCKeys(tenantID string) ([]PQCPublicKey, error) {
	req, err := http.NewRequest("GET", c.ServiceURL+"/api/v1/pqc/keys/"+url.PathEscape(tenantID), nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.APIKey) != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pqc keys request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError("pqc keys", resp)
	}
	var body struct {
		Keys []PQCPublicKey `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("failed to decode pqc keys response: %w", err)
	}
	return body.Keys, nil
}
