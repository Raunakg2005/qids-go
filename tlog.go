package qids

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign"
)

// TlogContext is the FIPS 204 context string the gateway signs tree heads under.
const TlogContext = "qids-sth-v1"

// SignedTreeHead is a tenant's signed tree head, as GET
// /api/v1/tlog/<tenant>/sth returns it. Only Statement and Signature are read.
type SignedTreeHead struct {
	// Statement is base64 of the exact signed bytes (canonical JSON).
	Statement string `json:"statement"`
	// Signature is base64 of the ML-DSA signature over the statement's bytes.
	Signature string `json:"signature"`
}

// TreeHeadClaims is what a verified tree head says.
type TreeHeadClaims struct {
	Version  int    `json:"v"`
	Type     string `json:"type"`
	TenantID string `json:"tenant_id"`
	TreeSize uint64 `json:"tree_size"`
	// RootHash is the hex SHA-256 root of the tenant's log at TreeSize.
	RootHash    string `json:"root_hash"`
	TimestampMs int64  `json:"timestamp_ms"`
	Algorithm   string `json:"alg"`
	KeyID       string `json:"kid"`
	// Statement is the exact signed bytes.
	Statement []byte `json:"-"`
}

// InclusionProof is GET /api/v1/tlog/<tenant>/inclusion: the hashes from a
// leaf to the root of the tree of TreeSize entries, hex.
type InclusionProof struct {
	Index     uint64   `json:"index"`
	TreeSize  uint64   `json:"tree_size"`
	LeafHash  string   `json:"leaf_hash"`
	AuditPath []string `json:"audit_path"`
}

// ConsistencyProof is GET /api/v1/tlog/<tenant>/consistency, hex.
type ConsistencyProof struct {
	First  uint64   `json:"first"`
	Second uint64   `json:"second"`
	Proof  []string `json:"proof"`
}

// ErrInvalidTlog matches every *TlogError with errors.Is.
var ErrInvalidTlog = errors.New("qids: transparency-log check failed")

// TlogReason says which check rejected a tree head or proof.
type TlogReason string

const (
	// TlogInvalidKey: the key is not a PEM SPKI ML-DSA public key.
	TlogInvalidKey TlogReason = "invalid_key"
	// TlogMalformedTreeHead: the statement or signature is missing or not
	// base64, or the statement is not a JSON object.
	TlogMalformedTreeHead TlogReason = "malformed_tree_head"
	// TlogBadSignature: the signature does not verify under this key and the
	// qids-sth-v1 context.
	TlogBadSignature TlogReason = "bad_signature"
	// TlogKeyMismatch: the statement's type, algorithm or key id is not this key's.
	TlogKeyMismatch TlogReason = "key_mismatch"
	// TlogTenantMismatch: the tree head belongs to a different tenant.
	TlogTenantMismatch TlogReason = "tenant_mismatch"
	// TlogIndexOutOfRange: the leaf index is not below the tree size.
	TlogIndexOutOfRange TlogReason = "index_out_of_range"
	// TlogProofTooLong: the proof has more hashes than the tree needs.
	TlogProofTooLong TlogReason = "proof_too_long"
	// TlogRootMismatch: the inclusion proof does not lead to the root.
	TlogRootMismatch TlogReason = "root_mismatch"
	// TlogBadSizes: not 0 < first size <= second size.
	TlogBadSizes TlogReason = "bad_sizes"
	// TlogFork: two trees of one size with different roots, or a proof between them.
	TlogFork TlogReason = "fork"
	// TlogEmptyProof: two sizes and no consistency proof.
	TlogEmptyProof TlogReason = "empty_proof"
	// TlogInconsistent: the consistency proof does not lead to both roots:
	// the log forked or an entry changed.
	TlogInconsistent TlogReason = "inconsistent"
)

// TlogError is a tree head or proof that failed an offline check.
type TlogError struct {
	Reason TlogReason
	Detail string
}

func (e *TlogError) Error() string {
	return fmt.Sprintf("qids: transparency-log check failed (%s): %s", e.Reason, e.Detail)
}

// Is makes errors.Is(err, ErrInvalidTlog) match every *TlogError.
func (e *TlogError) Is(target error) bool { return target == ErrInvalidTlog }

func tlogReject(reason TlogReason, detail string) error {
	return &TlogError{Reason: reason, Detail: detail}
}

// nodeHash is RFC 9162's interior node: SHA-256(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// ReceiptLeafHash is a receipt's transparency-log leaf hash:
// SHA-256(0x00 || statement).
func ReceiptLeafHash(receipt PQCReceipt) ([]byte, error) {
	statement, ok := decodeStrictBase64(receipt.Statement)
	if !ok {
		return nil, tlogReject(TlogMalformedTreeHead, "the receipt has no valid base64 statement")
	}
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(statement)
	return h.Sum(nil), nil
}

// VerifyInclusion checks, as RFC 9162 2.1.3.2 specifies, that leafHash is
// entry index of the tree of treeSize entries whose root is rootHash. A
// failure is a *TlogError.
func VerifyInclusion(leafHash []byte, index, treeSize uint64, auditPath [][]byte, rootHash []byte) error {
	if index >= treeSize {
		return tlogReject(TlogIndexOutOfRange, "leaf index outside the tree")
	}
	fn, sn, r := index, treeSize-1, leafHash
	for _, p := range auditPath {
		if sn == 0 {
			return tlogReject(TlogProofTooLong, "inclusion proof is too long")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(r, rootHash) {
		return tlogReject(TlogRootMismatch, "inclusion proof does not lead to the tree head's root")
	}
	return nil
}

// VerifyConsistency checks, as RFC 9162 2.1.4.2 specifies, that the tree of
// secondSize entries extends the tree of firstSize, rewriting nothing. This
// is the check a monitor runs between successive tree heads; a failure means
// the log forked or an entry changed. A failure is a *TlogError.
func VerifyConsistency(firstSize, secondSize uint64, firstRoot, secondRoot []byte, proof [][]byte) error {
	if firstSize == 0 || firstSize > secondSize {
		return tlogReject(TlogBadSizes, "need 0 < first_size <= second_size")
	}
	if firstSize == secondSize {
		if len(proof) != 0 || !bytes.Equal(firstRoot, secondRoot) {
			return tlogReject(TlogFork, "same size, different roots: the log forked")
		}
		return nil
	}
	if len(proof) == 0 {
		return tlogReject(TlogEmptyProof, "empty consistency proof")
	}
	path := proof
	// A first tree whose size is a power of two is a complete subtree: its
	// root starts the path.
	if firstSize&(firstSize-1) == 0 {
		path = append([][]byte{firstRoot}, proof...)
	}
	fn, sn := firstSize-1, secondSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return tlogReject(TlogProofTooLong, "consistency proof is too long")
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(fr, firstRoot) || !bytes.Equal(sr, secondRoot) {
		return tlogReject(TlogInconsistent, "the logs are not consistent: the log forked or an entry changed")
	}
	return nil
}

// VerifyTreeHead checks a signed tree head's ML-DSA signature offline and
// returns its claims.
//
// publicKeyPEM is the tenant's key, from a source you trust (GetPQCKeys once,
// then pinned). tenantID, when not empty, must be the log's tenant.
//
// The checks, in order (those of the Python SDK's verify_tree_head): the
// signature over the statement's exact bytes under the qids-sth-v1 context;
// that the statement is a tree head (type "qids-sth") naming this key's
// parameter set and id; and the tenant. A failure is a *TlogError whose
// Reason names the check; errors.Is(err, ErrInvalidTlog) matches it.
func VerifyTreeHead(sth SignedTreeHead, publicKeyPEM string, tenantID string) (*TreeHeadClaims, error) {
	algorithm, scheme, pk, raw, err := parsePQCPublicKey(publicKeyPEM)
	if err != nil {
		var re *ReceiptError
		if errors.As(err, &re) {
			return nil, tlogReject(TlogInvalidKey, re.Detail)
		}
		return nil, err
	}
	statement, ok1 := decodeStrictBase64(sth.Statement)
	signature, ok2 := decodeStrictBase64(sth.Signature)
	if !ok1 || !ok2 {
		return nil, tlogReject(TlogMalformedTreeHead, "malformed tree head: no valid base64 statement and signature")
	}
	if !scheme.Verify(pk, statement, signature, &sign.SignatureOpts{Context: TlogContext}) {
		return nil, tlogReject(TlogBadSignature, "tree head signature does not verify under this key")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(statement, &fields); err != nil {
		return nil, tlogReject(TlogMalformedTreeHead, "malformed tree head: the statement is not a JSON object")
	}
	sum := sha256.Sum256(raw)
	kind, _ := claimString(fields, "type")
	alg, _ := claimString(fields, "alg")
	kid, _ := claimString(fields, "kid")
	if kind != "qids-sth" || alg != algorithm || kid != hex.EncodeToString(sum[:])[:32] {
		return nil, tlogReject(TlogKeyMismatch, "the tree head names a different key, algorithm or type")
	}
	if tenantID != "" {
		if tenant, _ := claimString(fields, "tenant_id"); tenant != tenantID {
			return nil, tlogReject(TlogTenantMismatch, "the tree head belongs to a different tenant")
		}
	}
	claims := &TreeHeadClaims{Statement: statement}
	var typeErr *json.UnmarshalTypeError
	if err := json.Unmarshal(statement, claims); err != nil && !errors.As(err, &typeErr) {
		return nil, tlogReject(TlogMalformedTreeHead, "malformed tree head: the statement is not a JSON object")
	}
	return claims, nil
}

// getTlog GETs one of the public transparency-log routes into out.
func (c *QIDSClient) getTlog(op, tenantID, what string, query url.Values, out interface{}) error {
	u := c.ServiceURL + "/api/v1/tlog/" + url.PathEscape(tenantID) + "/" + what
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return err
	}
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

// GetTreeHead fetches the tenant's current signed tree head. Check it with
// VerifyTreeHead and the tenant's pinned key before trusting its root.
func (c *QIDSClient) GetTreeHead(tenantID string) (*SignedTreeHead, error) {
	var sth SignedTreeHead
	if err := c.getTlog("tree head", tenantID, "sth", nil, &sth); err != nil {
		return nil, err
	}
	return &sth, nil
}

// GetInclusionProof fetches the inclusion proof of a receipt's leaf (see
// ReceiptLeafHash) in the tree of treeSize entries; check it with
// VerifyInclusion against a verified tree head's root.
func (c *QIDSClient) GetInclusionProof(tenantID string, leafHash []byte, treeSize uint64) (*InclusionProof, error) {
	q := url.Values{"leaf_hash": {hex.EncodeToString(leafHash)}, "tree_size": {strconv.FormatUint(treeSize, 10)}}
	var p InclusionProof
	if err := c.getTlog("inclusion proof", tenantID, "inclusion", q, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// GetConsistencyProof fetches the consistency proof between two tree sizes;
// check it with VerifyConsistency against two verified tree heads' roots.
func (c *QIDSClient) GetConsistencyProof(tenantID string, first, second uint64) (*ConsistencyProof, error) {
	q := url.Values{"first": {strconv.FormatUint(first, 10)}, "second": {strconv.FormatUint(second, 10)}}
	var p ConsistencyProof
	if err := c.getTlog("consistency proof", tenantID, "consistency", q, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// DecodeHashes turns hex hashes (a proof's audit path) into bytes.
func DecodeHashes(hexHashes []string) ([][]byte, error) {
	out := make([][]byte, len(hexHashes))
	for i, h := range hexHashes {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil {
			return nil, fmt.Errorf("hash %d is not hex: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}
