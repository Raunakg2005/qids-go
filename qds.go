package qids

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// QDS mode: signatures with no trusted dealer. The gateway signs with keys
// it shares pairwise with each recipient through their KMEs and keeps no
// share; each recipient verifies on its own verifier node. See the gateway's
// docs/QDS_PROTOCOL.md. A preview: not in a gateway release yet.

// QDSSignResult is the answer of POST /api/v1/qds/sign.
type QDSSignResult struct {
	DocumentID   string `json:"document_id"`
	DocumentHash string `json:"document_hash"`
	SigID        string `json:"sig_id"`
	// Envelope is what a holder's node needs besides the document. It is not
	// secret; pass it to VerifierNode.Verify as it is.
	Envelope map[string]interface{} `json:"envelope"`
	// Delivered says, per holder: "stored", "not_configured",
	// "unreachable: ..." or "refused: ...".
	Delivered     map[string]string `json:"delivered"`
	SignedAtUTCMs int64             `json:"signed_at_utc_ms"`
	EntropySource []string          `json:"entropy_source"`
	QKDBacked     bool              `json:"qkd_backed"`
	// PQC is the ML-DSA receipt; check it with VerifyPQCReceipt.
	PQC *PQCReceipt `json:"pqc,omitempty"`
}

// QDSSign signs payload in QDS mode for holders (at least two). Unlike some
// calls, it is never retried: on a dropped connection, send it again with
// the same docID, and HTTP 409 means it was signed.
func (c *QIDSClient) QDSSign(docID string, payload []byte, holders []string) (*QDSSignResult, error) {
	var res QDSSignResult
	err := c.postJSON("qds sign", "/api/v1/qds/sign", map[string]interface{}{
		"document_id": docID,
		"payload_b64": base64.StdEncoding.EncodeToString(payload),
		"holders":     holders,
	}, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// ErrNoNodeToken is returned by VerifierNode.Verify before any request is
// sent when the node has no operator token.
var ErrNoNodeToken = errors.New("qids: verifying on a node needs its operator token")

// QDSVerdict is a verifier node's answer.
type QDSVerdict struct {
	Holder   string `json:"holder"`
	SigID    string `json:"sig_id"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail"`
}

// VerifierNode is a recipient's own verifier node (python -m qids.qds.node).
// Deliver needs no credentials: the node checks the signer's tag. Verify
// needs the node operator's token, because verifying binds the node's key to
// the document.
type VerifierNode struct {
	URL        string
	Token      string `json:"-"`
	HTTPClient *http.Client
}

// NewVerifierNode returns a client for the node at url.
func NewVerifierNode(url, token string) *VerifierNode {
	return &VerifierNode{URL: strings.TrimRight(url, "/"), Token: token,
		HTTPClient: &http.Client{Timeout: 30 * time.Second}}
}

func (n *VerifierNode) post(op, path string, body interface{}, auth bool) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", n.URL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth {
		if strings.TrimSpace(n.Token) == "" {
			return nil, ErrNoNodeToken
		}
		req.Header.Set("Authorization", "Bearer "+n.Token)
	}
	resp, err := n.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s request failed: %w", op, err)
	}
	return resp, nil
}

// Deliver hands the node an envelope. stored is false, with the node's
// reason, if it refused it (for example an envelope that is not the signer's).
func (n *VerifierNode) Deliver(envelope map[string]interface{}) (stored bool, reason string, err error) {
	resp, err := n.post("qds deliver", "/v1/qds/signatures", map[string]interface{}{"envelope": envelope}, false)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return false, "", newAPIError("qds deliver", resp)
	}
	var out struct {
		Stored bool   `json:"stored"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, "", fmt.Errorf("failed to decode qds deliver response: %w", err)
	}
	return out.Stored, out.Reason, nil
}

// Verify asks the node for its verdict on document under envelope.
func (n *VerifierNode) Verify(document []byte, envelope map[string]interface{}) (*QDSVerdict, error) {
	resp, err := n.post("qds verify", "/v1/qds/verify", map[string]interface{}{
		"document_b64": base64.StdEncoding.EncodeToString(document),
		"envelope":     envelope,
	}, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, newAPIError("qds verify", resp)
	}
	var v QDSVerdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("failed to decode qds verify response: %w", err)
	}
	return &v, nil
}
