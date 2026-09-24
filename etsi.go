package qids

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ETSIKey represents a quantum key slice delivered by an ETSI GS QKD 014 appliance.
type ETSIKey struct {
	KeyID    string
	KeyBytes []byte
	SizeBits int
}

// ToBitList converts key bytes into a slice of integers (0 or 1).
func (k *ETSIKey) ToBitList() []int {
	bits := make([]int, 0, k.SizeBits)
	for _, b := range k.KeyBytes {
		for shift := 7; shift >= 0; shift-- {
			bits = append(bits, int((b>>shift)&1))
			if len(bits) == k.SizeBits {
				return bits
			}
		}
	}
	return bits
}

// ETSIStatus represents KMS key availability metrics.
type ETSIStatus struct {
	SourceKMEID      string `json:"source_KME_ID"`
	DestinationKMEID string `json:"destination_KME_ID"`
	SourceSAEID      string `json:"source_SAE_ID"`
	DestinationSAEID string `json:"destination_SAE_ID"`
	KeySize          int    `json:"key_size"`
	StoredKeyCount   int    `json:"stored_key_count"`
	MaxKeyCount      int    `json:"max_key_count"`
}

// ETSI014Client communicates with ETSI GS QKD 014 KMS appliances.
type ETSI014Client struct {
	BaseURL          string
	SourceSAEID      string
	DestinationSAEID string
	HTTPClient       *http.Client
}

// NewETSI014Client creates a new ETSI client.
func NewETSI014Client(baseURL, sourceSAE, destSAE string) *ETSI014Client {
	return &ETSI014Client{
		BaseURL:          strings.TrimRight(baseURL, "/"),
		SourceSAEID:      sourceSAE,
		DestinationSAEID: destSAE,
		HTTPClient:       &http.Client{Timeout: 10 * time.Second},
	}
}

// GetStatus queries available key material status.
func (c *ETSI014Client) GetStatus() (*ETSIStatus, error) {
	url := fmt.Sprintf("%s/api/v1/keys/%s/status", c.BaseURL, c.DestinationSAEID)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to query ETSI status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ETSI KMS returned HTTP %d", resp.StatusCode)
	}

	var status ETSIStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode ETSI status JSON: %w", err)
	}
	return &status, nil
}

// GetEncKeys requests new encryption keys (Alice/Sender side).
func (c *ETSI014Client) GetEncKeys(number, sizeBits int) ([]ETSIKey, error) {
	url := fmt.Sprintf("%s/api/v1/keys/%s/enc_keys", c.BaseURL, c.DestinationSAEID)
	reqBody, _ := json.Marshal(map[string]interface{}{
		"number": number,
		"size":   sizeBits,
	})

	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to request enc_keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ETSI KMS enc_keys returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Keys []struct {
			KeyID string `json:"key_ID"`
			Key   string `json:"key"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode enc_keys JSON: %w", err)
	}

	out := make([]ETSIKey, len(result.Keys))
	for i, k := range result.Keys {
		raw, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			raw, _ = hex.DecodeString(k.Key)
		}
		out[i] = ETSIKey{
			KeyID:    k.KeyID,
			KeyBytes: raw,
			SizeBits: sizeBits,
		}
	}
	return out, nil
}

// GetDecKeys retrieves matching decryption keys by key IDs (Bob/Receiver side).
func (c *ETSI014Client) GetDecKeys(keyIDs []string) ([]ETSIKey, error) {
	url := fmt.Sprintf("%s/api/v1/keys/%s/dec_keys", c.BaseURL, c.DestinationSAEID)
	type keyIDItem struct {
		KeyID string `json:"key_ID"`
	}
	items := make([]keyIDItem, len(keyIDs))
	for i, id := range keyIDs {
		items[i] = keyIDItem{KeyID: id}
	}
	reqBody, _ := json.Marshal(map[string]interface{}{"key_IDs": items})

	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to request dec_keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ETSI KMS dec_keys returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Keys []struct {
			KeyID string `json:"key_ID"`
			Key   string `json:"key"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode dec_keys JSON: %w", err)
	}

	out := make([]ETSIKey, len(result.Keys))
	for i, k := range result.Keys {
		raw, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			raw, _ = hex.DecodeString(k.Key)
		}
		out[i] = ETSIKey{
			KeyID:    k.KeyID,
			KeyBytes: raw,
			SizeBits: len(raw) * 8,
		}
	}
	return out, nil
}
