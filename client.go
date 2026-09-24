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
}

// VerifyResult holds the outcome of a signature verification.
type VerifyResult struct {
	DocumentID         string  `json:"document_id"`
	Status             string  `json:"status"`
	IsValid            bool    `json:"is_valid"`
	ObservedErrorRate  float64 `json:"observed_error_rate"`
	ThresholdErrorRate float64 `json:"threshold_error_rate"`
	Reason             string  `json:"reason"`
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
	// Every /api/v1 call requires it; without it the Gateway returns 401.
	APIKey     string
	HTTPClient *http.Client
}

// NewQIDSClient creates a new QIDS client.
//
// Deprecated: use NewQIDSClientWithKey. The Gateway requires an API key, so a
// client built without one can only reach unauthenticated endpoints.
func NewQIDSClient(serviceURL, nodeID string) *QIDSClient {
	return NewQIDSClientWithKey(serviceURL, nodeID, "")
}

// NewQIDSClientWithKey creates a client authenticated with a Gateway API key.
func NewQIDSClientWithKey(serviceURL, nodeID, apiKey string) *QIDSClient {
	return &QIDSClient{
		ServiceURL: strings.TrimRight(serviceURL, "/"),
		NodeID:     nodeID,
		APIKey:     apiKey,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// postJSON issues an authenticated JSON POST to the Gateway.
func (c *QIDSClient) postJSON(url string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	return c.HTTPClient.Do(req)
}

// Sign submits a payload to be signed across designated recipients.
//
// The payload travels as payload_b64, its exact bytes. Earlier versions sent
// string(payload), which JSON-encodes every invalid UTF-8 byte as U+FFFD, so
// two different binary documents reached the gateway as the same text and a
// signature over one verified the other.
func (c *QIDSClient) Sign(docID string, payload []byte, recipients []string) (*SignResult, error) {
	url := fmt.Sprintf("%s/api/v1/sign", c.ServiceURL)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"document_id": docID,
		"payload_b64": base64.StdEncoding.EncodeToString(payload),
		"recipients":  recipients,
	})

	resp, err := c.postJSON(url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sign returned HTTP %d", resp.StatusCode)
	}

	var res SignResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode sign response: %w", err)
	}
	return &res, nil
}

// Verify submits a signature tag to be verified.
func (c *QIDSClient) Verify(docID string, payload []byte, tag, keyID string) (*VerifyResult, error) {
	url := fmt.Sprintf("%s/api/v1/verify", c.ServiceURL)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"document_id": docID,
		"payload_b64": base64.StdEncoding.EncodeToString(payload),
		"hash_tag":    tag,
		"key_id":      keyID,
	})

	resp, err := c.postJSON(url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("verify request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verify returned HTTP %d", resp.StatusCode)
	}

	var res VerifyResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode verify response: %w", err)
	}
	return &res, nil
}
