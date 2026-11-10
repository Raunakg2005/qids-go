package qids

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/cloudflare/circl/sign"
)

// WitnessContext is the FIPS 204 context string witnesses sign co-signatures under.
const WitnessContext = "qids-witness-v1"

const (
	// TlogBadCosignature: a co-signature is malformed, or does not verify
	// under the witness key and the qids-witness-v1 context.
	TlogBadCosignature TlogReason = "bad_cosignature"
	// TlogCosignatureMismatch: the co-signature names another witness, or
	// another head, tenant or log key than the one checked.
	TlogCosignatureMismatch TlogReason = "cosignature_mismatch"
	// TlogWitnessIsLogKey: a trusted witness key is the log's own key, which
	// the operator holds, so it could make up the quorum alone.
	TlogWitnessIsLogKey TlogReason = "witness_is_log_key"
	// TlogQuorumNotMet: no tree head has the quorum of valid co-signatures
	// from distinct trusted witnesses.
	TlogQuorumNotMet TlogReason = "quorum_not_met"
)

// Cosignature is one witness's co-signature on a tree head.
type Cosignature struct {
	// Witness is the witness key's id: the first 32 hex characters of
	// SHA-256 over the raw key.
	Witness string `json:"witness"`
	// Statement is base64 of the exact signed bytes (canonical JSON).
	Statement string `json:"statement"`
	// Signature is base64 of the ML-DSA-65 signature over the statement's bytes.
	Signature string `json:"signature"`
}

// CosignedHead is a tree head and the co-signatures the gateway holds for it.
type CosignedHead struct {
	STH          SignedTreeHead `json:"sth"`
	Cosignatures []Cosignature  `json:"cosignatures"`
}

// CosignedTreeHeads is GET /api/v1/tlog/<tenant>/cosigned: recent co-signed
// heads, largest first, in Heads; the largest also at the top, as an older
// gateway served it alone.
type CosignedTreeHeads struct {
	Heads        []CosignedHead `json:"heads"`
	STH          SignedTreeHead `json:"sth"`
	Cosignatures []Cosignature  `json:"cosignatures"`
}

// CosignatureClaims is what a verified co-signature says.
type CosignatureClaims struct {
	Witness  string
	TenantID string
	TreeSize uint64
	RootHash string
	LogKeyID string
	// CosignedAtMs is when the witness co-signed, by its own clock.
	CosignedAtMs int64
	// Statement is the exact signed bytes.
	Statement []byte
}

// CosignedTreeHeadClaims is a tree head that a quorum of trusted witnesses co-signed.
type CosignedTreeHeadClaims struct {
	TreeHeadClaims
	// Witnesses are the ids of the trusted witnesses whose co-signatures verified, sorted.
	Witnesses []string
	// CosignedAtMs is the quorum-th most recent of their co-signing times, by
	// the witnesses' clocks: how fresh the witnessing is. The head's own
	// timestamp is the operator's.
	CosignedAtMs int64
}

type witnessKey struct {
	scheme sign.Scheme
	pk     sign.PublicKey
	kid    string
}

// parseWitnessKey reads a trusted witness key: ML-DSA-65 only, as qids.witness requires.
func parseWitnessKey(publicKeyPEM string) (*witnessKey, error) {
	algorithm, scheme, pk, raw, err := parsePQCPublicKey(publicKeyPEM)
	if err != nil {
		var re *ReceiptError
		if errors.As(err, &re) {
			return nil, tlogReject(TlogInvalidKey, re.Detail)
		}
		return nil, err
	}
	if algorithm != "ML-DSA-65" {
		return nil, tlogReject(TlogInvalidKey, "a witness key must be ML-DSA-65")
	}
	sum := sha256.Sum256(raw)
	return &witnessKey{scheme: scheme, pk: pk, kid: hex.EncodeToString(sum[:])[:32]}, nil
}

func checkCosignature(cosig Cosignature, key *witnessKey, head *TreeHeadClaims) (*CosignatureClaims, error) {
	statement, ok1 := decodeStrictBase64(cosig.Statement)
	signature, ok2 := decodeStrictBase64(cosig.Signature)
	if !ok1 || !ok2 {
		return nil, tlogReject(TlogBadCosignature, "malformed co-signature")
	}
	if !key.scheme.Verify(key.pk, statement, signature, &sign.SignatureOpts{Context: WitnessContext}) {
		return nil, tlogReject(TlogBadCosignature, "co-signature does not verify under this witness key")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(statement, &fields); err != nil {
		return nil, tlogReject(TlogBadCosignature, "malformed co-signature")
	}
	kind, _ := claimString(fields, "type")
	witness, _ := claimString(fields, "witness")
	if kind != "qids-cosignature" || witness != key.kid {
		return nil, tlogReject(TlogCosignatureMismatch, "the co-signature names another witness or type")
	}
	tenant, okTenant := claimString(fields, "tenant_id")
	root, okRoot := claimString(fields, "root_hash")
	var size uint64
	okSize := json.Unmarshal(fields["tree_size"], &size) == nil
	switch {
	case !okTenant || tenant != head.TenantID:
		return nil, tlogReject(TlogCosignatureMismatch, "the co-signature is for another head (tenant_id)")
	case !okSize || size != head.TreeSize:
		return nil, tlogReject(TlogCosignatureMismatch, "the co-signature is for another head (tree_size)")
	case !okRoot || root != head.RootHash:
		return nil, tlogReject(TlogCosignatureMismatch, "the co-signature is for another head (root_hash)")
	}
	if logKid, _ := claimString(fields, "log_kid"); logKid != head.KeyID {
		return nil, tlogReject(TlogCosignatureMismatch, "the co-signature is for a head under another log key")
	}
	var at int64
	if raw, present := fields["cosigned_at_ms"]; !present || json.Unmarshal(raw, &at) != nil {
		return nil, tlogReject(TlogBadCosignature, "malformed co-signature: cosigned_at_ms")
	}
	return &CosignatureClaims{Witness: key.kid, TenantID: tenant, TreeSize: size, RootHash: root,
		LogKeyID: head.KeyID, CosignedAtMs: at, Statement: statement}, nil
}

// VerifyCosignature checks one witness's co-signature on a tree head whose
// claims VerifyTreeHead returned, and returns what the witness signed.
// Nothing here contacts the gateway.
//
// The checks (those of the Python SDK's qids.witness.verify_cosignature): an
// ML-DSA-65 signature over the statement's exact bytes under the
// qids-witness-v1 context; a qids-cosignature statement naming this witness
// key; the same tenant, tree size and root as the head; and the head's log
// key. witnessPublicKeyPEM is the witness's key, pinned from a source you
// trust. A failure is a *TlogError; errors.Is(err, ErrInvalidTlog) matches it.
func VerifyCosignature(cosig Cosignature, witnessPublicKeyPEM string, head *TreeHeadClaims) (*CosignatureClaims, error) {
	key, err := parseWitnessKey(witnessPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return checkCosignature(cosig, key, head)
}

// VerifyCosignedTreeHead verifies the largest tree head that at least quorum
// distinct trusted witnesses co-signed. Nothing here contacts the gateway.
//
// A gateway can show one history to a monitor and another to everyone else,
// each signed with the tenant's key, which the operator holds. A witness
// co-signs a head only if it extends the last one it co-signed, so a head
// that enough witnesses you trust co-signed is on the one history they all saw.
//
// The checks, as the Python SDK's qids.witness.verify_cosigned_tree_head
// makes them: each head's signature under the log key (and tenant, if not
// empty); that no trusted witness key is the log's own key; and each
// co-signature from a trusted witness, as VerifyCosignature does. A
// co-signature that fails counts for nothing, and a witness counts once. The
// largest head with quorum witnesses wins: on a busy log the newest head may
// have only some of them yet.
//
// cosigned is what GetCosignedTreeHead returns; logPublicKeyPEM and
// witnessPublicKeyPEMs are pinned keys; quorum is at least 1. A failure to
// verify is a *TlogError; errors.Is(err, ErrInvalidTlog) matches it.
func VerifyCosignedTreeHead(cosigned CosignedTreeHeads, logPublicKeyPEM string, witnessPublicKeyPEMs []string,
	quorum int, tenantID string) (*CosignedTreeHeadClaims, error) {
	if quorum < 1 {
		return nil, errors.New("qids: quorum must be at least 1")
	}
	trusted := map[string]*witnessKey{}
	for _, pemKey := range witnessPublicKeyPEMs {
		key, err := parseWitnessKey(pemKey)
		if err != nil {
			return nil, err
		}
		trusted[key.kid] = key
	}
	heads := cosigned.Heads
	if heads == nil {
		heads = []CosignedHead{{STH: cosigned.STH, Cosignatures: cosigned.Cosignatures}}
	}
	var best *TreeHeadClaims
	var bestTimes map[string]int64
	bestCount, reason := 0, "no co-signed head"
	for _, head := range heads {
		claims, err := VerifyTreeHead(head.STH, logPublicKeyPEM, tenantID)
		if err != nil {
			if !errors.Is(err, ErrInvalidTlog) {
				return nil, err
			}
			reason = err.Error()
			continue
		}
		if _, isWitness := trusted[claims.KeyID]; isWitness {
			// The operator holds the log key: as a "witness" it would forge the quorum.
			return nil, tlogReject(TlogWitnessIsLogKey, "a trusted witness key is the log's own key")
		}
		times := map[string]int64{}
		for _, cosig := range head.Cosignatures {
			key, ok := trusted[cosig.Witness]
			if !ok {
				continue
			}
			body, err := checkCosignature(cosig, key, claims)
			if err != nil {
				continue // a bad one counts for nothing; the quorum decides
			}
			if at, seen := times[key.kid]; !seen || body.CosignedAtMs > at {
				times[key.kid] = body.CosignedAtMs
			}
		}
		if len(times) > bestCount {
			bestCount = len(times)
		}
		if len(times) >= quorum && (best == nil || claims.TreeSize > best.TreeSize) {
			best, bestTimes = claims, times
		}
	}
	if best == nil {
		return nil, tlogReject(TlogQuorumNotMet, fmt.Sprintf(
			"no tree head has %d valid co-signature(s) from trusted witnesses (at most %d; %s)",
			quorum, bestCount, reason))
	}
	witnesses := make([]string, 0, len(bestTimes))
	recent := make([]int64, 0, len(bestTimes))
	for kid, at := range bestTimes {
		witnesses = append(witnesses, kid)
		recent = append(recent, at)
	}
	sort.Strings(witnesses)
	sort.Slice(recent, func(i, j int) bool { return recent[i] > recent[j] })
	return &CosignedTreeHeadClaims{TreeHeadClaims: *best, Witnesses: witnesses, CosignedAtMs: recent[quorum-1]}, nil
}

// GetCosignedTreeHead fetches the tree heads witnesses co-signed, with their
// co-signatures (GET /api/v1/tlog/<tenant>/cosigned; no API key). Check them
// with VerifyCosignedTreeHead, the tenant's pinned key and the witness keys
// you trust.
func (c *QIDSClient) GetCosignedTreeHead(tenantID string) (*CosignedTreeHeads, error) {
	var out CosignedTreeHeads
	if err := c.getTlog("co-signed tree head", tenantID, "cosigned", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
