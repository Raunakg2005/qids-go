package qids

import (
	"bytes"
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
	HTTPClient *http.Client
}

// NewQIDSClient creates a new QIDS client.
func NewQIDSClient(serviceURL, nodeID string) *QIDSClient {
	return &QIDSClient{
		ServiceURL: strings.TrimRight(serviceURL, "/"),
		NodeID:     nodeID,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Sign submits a payload to be signed across designated recipients.
func (c *QIDSClient) Sign(docID string, payload []byte, recipients []string) (*SignResult, error) {
	url := fmt.Sprintf("%s/api/v1/sign", c.ServiceURL)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"document_id": docID,
		"payload":     string(payload),
		"recipients":  recipients,
	})

	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(reqBody))
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
		"payload":     string(payload),
		"hash_tag":    tag,
		"key_id":      keyID,
	})

	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(reqBody))
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
