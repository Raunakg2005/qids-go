package qids

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SignatureTag represents one recipient's signature tag.
type SignatureTag struct {
	RecipientSAEID string `json:"recipient_sae_id"`
	HashTag        string `json:"hash_tag"`
	TagLengthBits  int    `json:"tag_length_bits"`
	KeyID          string `json:"key_id"`
}

// SignResult holds the output of a signing operation.
type SignResult struct {
	DocumentID    string         `json:"document_id"`
	DocumentHash  string         `json:"document_hash"`
	SignatureTags []SignatureTag `json:"signature_tags"`
	SignedAtMs    int64          `json:"signed_at_utc_ms"`
	Algorithm     string         `json:"algorithm"`
	// EntropySource says where the one-time key actually came from:
	// "CSPRNG", "ETSI-GS-QKD-014", or "ETSI-GS-QKD-014-MOCK" (a KMS that
	// declares itself a mock).
	EntropySource []string `json:"entropy_source"`
	// QKDBacked is true only when the key came from an ETSI GS QKD 014 KMS
	// that is not a mock.
	QKDBacked bool `json:"qkd_backed"`
	// PQC is the receipt's ML-DSA (FIPS 204) signature, which anyone can
	// check offline with VerifyPQCReceipt and the tenant's published key.
	// Nil from a gateway older than 1.4.0.
	PQC *PQCReceipt `json:"pqc,omitempty"`
}

// VerifyResult holds the outcome of a signature verification.
type VerifyResult struct {
	DocumentID         string  `json:"document_id"`
	Status             string  `json:"status"`
	IsValid            bool    `json:"is_valid"`
	ObservedErrorRate  float64 `json:"observed_error_rate"`
	ThresholdErrorRate float64 `json:"threshold_error_rate"`
	Reason             string  `json:"reason"`
	// Threat is the gateway's attribution of a rejection: benign, forgery,
	// replay, impersonation or unauthorized_verification.
	Threat     string                 `json:"threat"`
	Confidence float64                `json:"confidence"`
	Evidence   map[string]interface{} `json:"evidence"`
}

// CrossVerifyResult holds dispute resolution consistency checks.
type CrossVerifyResult struct {
	DocumentID                 string `json:"document_id"`
	IsConsistent               bool   `json:"is_consistent"`
	HammingDistance            int    `json:"hamming_distance"`
	MaxAllowedDiscrepancy      int    `json:"maximum_allowed_discrepancy"`
	RepudiationAttemptDetected bool   `json:"repudiation_attempt_detected"`
}

// QIDSClient is a high-level client for the QIDS service daemon.
type QIDSClient struct {
	ServiceURL string
	NodeID     string
	// APIKey authenticates against the Gateway (sk_live_... / sk_test_...).
	// Every /api/v1 call requires it; a client without one fails with
	// ErrNoAPIKey before sending anything. It is never marshalled to JSON,
	// and fmt prints the client with the key redacted.
	APIKey     string `json:"-"`
	HTTPClient *http.Client
}

// NewClient creates a client authenticated with a Gateway API key, and
// rejects an empty key.
func NewClient(serviceURL, nodeID, apiKey string) (*QIDSClient, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, ErrNoAPIKey
	}
	return NewQIDSClientWithKey(serviceURL, nodeID, apiKey), nil
}

// NewQIDSClient creates a client without an API key. Its Sign and Verify
// calls fail with ErrNoAPIKey.
//
// Deprecated: use NewClient. The Gateway requires an API key on every
// /api/v1 call.
func NewQIDSClient(serviceURL, nodeID string) *QIDSClient {
	return NewQIDSClientWithKey(serviceURL, nodeID, "")
}

// NewQIDSClientWithKey creates a client authenticated with a Gateway API key.
// Prefer NewClient, which rejects an empty key up front.
func NewQIDSClientWithKey(serviceURL, nodeID, apiKey string) *QIDSClient {
	return &QIDSClient{
		ServiceURL: strings.TrimRight(serviceURL, "/"),
		NodeID:     nodeID,
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Format prints the client with its API key redacted, for every verb
// (%v, %+v, %#v, %s, ...), so logging a client never leaks the key.
func (c QIDSClient) Format(f fmt.State, verb rune) {
	key := "<none>"
	if c.APIKey != "" {
		key = "<redacted>"
	}
	fmt.Fprintf(f, "QIDSClient{ServiceURL:%q NodeID:%q APIKey:%s}", c.ServiceURL, c.NodeID, key)
}

// postJSON issues an authenticated JSON POST to the Gateway and decodes a 200
// response into out. Any other status becomes an *APIError.
func (c *QIDSClient) postJSON(op, path string, body interface{}, out interface{}) error {
	if strings.TrimSpace(c.APIKey) == "" {
		return ErrNoAPIKey
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", c.ServiceURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", op, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newAPIError(op, resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("failed to decode %s response: %w", op, err)
	}
	return nil
}

// Sign submits a payload to be signed across designated recipients.
//
// The payload travels as payload_b64, its exact bytes. Earlier versions sent
// string(payload), which JSON-encodes every invalid UTF-8 byte as U+FFFD, so
// two different binary documents reached the gateway as the same text and a
// signature over one verified the other.
func (c *QIDSClient) Sign(docID string, payload []byte, recipients []string) (*SignResult, error) {
	var res SignResult
	err := c.postJSON("sign", "/api/v1/sign", map[string]interface{}{
		"document_id": docID,
		"payload_b64": base64.StdEncoding.EncodeToString(payload),
		"recipients":  recipients,
	}, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// VerifyTag verifies one recipient's signature tag, as returned by Sign. It
// presents the tag as tag.RecipientSAEID, so each recipient's verification is
// attributed to that recipient (and its first-presentation freshness check
// applies to it), not to the document's first recipient.
func (c *QIDSClient) VerifyTag(docID string, payload []byte, tag SignatureTag) (*VerifyResult, error) {
	body := map[string]interface{}{
		"document_id": docID,
		"payload_b64": base64.StdEncoding.EncodeToString(payload),
		"hash_tag":    tag.HashTag,
		"key_id":      tag.KeyID,
	}
	if tag.RecipientSAEID != "" {
		body["recipient_sae_id"] = tag.RecipientSAEID
	}
	var res VerifyResult
	if err := c.postJSON("verify", "/api/v1/verify", body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Verify verifies a signature tag without naming the recipient presenting it,
// so the gateway attributes it to the document's first recipient. Use
// VerifyTag to verify as a specific recipient.
func (c *QIDSClient) Verify(docID string, payload []byte, tag, keyID string) (*VerifyResult, error) {
	return c.VerifyTag(docID, payload, SignatureTag{HashTag: tag, KeyID: keyID})
}
