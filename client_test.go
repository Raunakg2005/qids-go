package qids

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// binaryDoc is not valid UTF-8. string(binaryDoc) JSON-encodes 0xff as
// U+FFFD, which is how two different binary documents used to share a
// signature; payload_b64 must carry these exact bytes.
var binaryDoc = []byte{0xff, 'P', 'A', 'Y', ' ', '1', '0', '0', 0x00, 0x01}

func TestSignSendsAuthAndExactBytes(t *testing.T) {
	var gotAuth string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"document_id":"d1","signature_tags":[]}`))
	}))
	defer srv.Close()

	c := NewQIDSClientWithKey(srv.URL, "SAE_Alice", "sk_test_abc")
	if _, err := c.Sign("d1", binaryDoc, []string{"SAE_Bob"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sk_test_abc" {
		t.Fatalf("Authorization header = %q", gotAuth)
	}
	if _, present := gotBody["payload"]; present {
		t.Fatal("client sent lossy text 'payload'; must send only payload_b64")
	}
	decoded, err := base64.StdEncoding.DecodeString(gotBody["payload_b64"].(string))
	if err != nil || !bytes.Equal(decoded, binaryDoc) {
		t.Fatalf("payload_b64 does not round-trip to the exact bytes: %v %x", err, decoded)
	}
}

// TestAgainstRealGateway runs the binary-substitution exploit end to end.
// Set QIDS_TEST_GATEWAY_URL and QIDS_TEST_API_KEY to a running gateway.
func TestAgainstRealGateway(t *testing.T) {
	url, key := os.Getenv("QIDS_TEST_GATEWAY_URL"), os.Getenv("QIDS_TEST_API_KEY")
	if url == "" || key == "" {
		t.Skip("QIDS_TEST_GATEWAY_URL / QIDS_TEST_API_KEY not set")
	}
	c := NewQIDSClientWithKey(url, "SAE_Alice", key)
	other := append([]byte{0xfe}, binaryDoc[1:]...)
	docID := "go-bin-" + base64.RawURLEncoding.EncodeToString([]byte(t.Name()+os.Getenv("QIDS_TEST_NONCE")))

	sig, err := c.Sign(docID, binaryDoc, []string{"SAE_Bob"})
	if err != nil {
		t.Fatal(err)
	}
	tag := sig.SignatureTags[0]
	good, err := c.Verify(docID, binaryDoc, tag.HashTag, tag.KeyID)
	if err != nil || !good.IsValid {
		t.Fatalf("genuine document rejected: %v %+v", err, good)
	}
	forged, err := c.Verify(docID, other, tag.HashTag, tag.KeyID)
	if err != nil || forged.IsValid {
		t.Fatalf("different binary document accepted with the same signature: %v %+v", err, forged)
	}
}
