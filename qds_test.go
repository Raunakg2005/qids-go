package qids

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestQDSSignSendsHoldersAndMapsTheAnswer(t *testing.T) {
	var body map[string]interface{}
	var path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		_, _ = w.Write([]byte(`{"document_id":"d1","sig_id":"s1","envelope":{"v":"qids-qds/1"},
			"delivered":{"bob":"stored"},"entropy_source":["ETSI-GS-QKD-014-MOCK"],"qkd_backed":false,
			"pqc":{"algorithm":"ML-DSA-65","key_id":"k","statement":"c3Q=","signature":"c2c="}}`))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, "app", "sk_test_x")
	res, err := c.QDSSign("d1", binaryDoc, []string{"bob", "charlie"})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/v1/qds/sign" || auth != "Bearer sk_test_x" {
		t.Fatalf("path %q auth %q", path, auth)
	}
	if body["payload_b64"] != base64.StdEncoding.EncodeToString(binaryDoc) {
		t.Fatalf("payload not sent as its exact bytes: %v", body["payload_b64"])
	}
	if res.SigID != "s1" || res.Delivered["bob"] != "stored" || res.QKDBacked || res.PQC.KeyID != "k" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestVerifierNodeTokenRules(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/qds/signatures" {
			if r.Header.Get("Authorization") != "" {
				t.Error("deliver must not send a token")
			}
			_, _ = w.Write([]byte(`{"stored":true}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer op" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"holder":"bob","sig_id":"s1","accepted":true,"reason":"ok"}`))
	}))
	defer srv.Close()
	if stored, _, err := NewVerifierNode(srv.URL, "").Deliver(map[string]interface{}{}); err != nil || !stored {
		t.Fatalf("deliver: %v %v", stored, err)
	}
	if _, err := NewVerifierNode(srv.URL, "").Verify([]byte("d"), nil); !errors.Is(err, ErrNoNodeToken) {
		t.Fatalf("no token: %v", err)
	}
	if _, err := NewVerifierNode(srv.URL, "wrong").Verify([]byte("d"), nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong token: %v", err)
	}
	v, err := NewVerifierNode(srv.URL, "op").Verify([]byte("d"), nil)
	if err != nil || !v.Accepted || v.Holder != "bob" {
		t.Fatalf("verify: %+v %v", v, err)
	}
}

// The end-of-phase audit (gateway audit 2.84).

func TestVerifierNodeRefusesAnEmptyDocumentBeforeSending(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer srv.Close()
	for _, doc := range [][]byte{nil, {}} {
		if _, err := NewVerifierNode(srv.URL, "op").Verify(doc, nil); !errors.Is(err, ErrEmptyDocument) {
			t.Fatalf("empty document: %v", err)
		}
	}
	if calls != 0 {
		t.Fatalf("%d requests sent", calls)
	}
}

func TestVerifierNodeKeepsItsTokenOutOfLogs(t *testing.T) {
	n := NewVerifierNode("http://127.0.0.1:1", "node-op-secret")
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(f, n); strings.Contains(out, "node-op-secret") {
			t.Fatalf("%s leaks the token: %s", f, out)
		}
		if out := fmt.Sprintf(f, *n); strings.Contains(out, "node-op-secret") {
			t.Fatalf("%s leaks the token: %s", f, out)
		}
	}
	bare := &VerifierNode{URL: "http://127.0.0.1:1"} // no HTTPClient: no panic
	if _, _, err := bare.Deliver(map[string]interface{}{}); err == nil {
		t.Fatal("expected a connection error")
	}
}

func TestVerifierNodeAnswersThatAreNotVerdicts(t *testing.T) {
	answer := func(status int, body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	for _, c := range []struct {
		status int
		body   string
	}{{200, "<html>"}, {200, "[]"}, {200, `{"reason":"ok"}`}, {200, `{"accepted":"false"}`}, {404, `{"error":"Not found"}`}} {
		if _, err := NewVerifierNode(answer(c.status, c.body), "op").Verify([]byte("d"), nil); err == nil {
			t.Fatalf("verify %d %s: no error", c.status, c.body)
		}
	}
	stored, reason, err := NewVerifierNode(answer(400, `{"stored":false,"reason":"envelope_unauthentic"}`), "").
		Deliver(map[string]interface{}{})
	if err != nil || stored || reason != "envelope_unauthentic" {
		t.Fatalf("refused: %v %q %v", stored, reason, err)
	}
	for _, c := range []struct {
		status int
		body   string
	}{{404, `{"error":"Not found"}`}, {200, `{"stored":false}`}, {200, "<html>"}} {
		if _, _, err := NewVerifierNode(answer(c.status, c.body), "").Deliver(map[string]interface{}{}); err == nil {
			t.Fatalf("deliver %d %s: no error", c.status, c.body)
		}
	}
}

// With QIDS_TEST_QDS_GATEWAY_URL, QIDS_TEST_API_KEY, QIDS_TEST_QDS_NODES
// ("name=url,...") and QIDS_TEST_QDS_TOKENS ("name=token,..."): sign on a real
// gateway in QDS mode and verify on the real nodes.
func TestQDSAgainstRealGateway(t *testing.T) {
	gw := os.Getenv("QIDS_TEST_QDS_GATEWAY_URL")
	if gw == "" {
		t.Skip("set QIDS_TEST_QDS_GATEWAY_URL")
	}
	pairs := func(v string) map[string]string {
		m := map[string]string{}
		for _, p := range strings.Split(v, ",") {
			if k, val, ok := strings.Cut(p, "="); ok {
				m[k] = val
			}
		}
		return m
	}
	nodes, tokens := pairs(os.Getenv("QIDS_TEST_QDS_NODES")), pairs(os.Getenv("QIDS_TEST_QDS_TOKENS"))
	holders := make([]string, 0, len(nodes))
	for name := range nodes {
		holders = append(holders, name)
	}
	c, _ := NewClient(gw, "go", os.Getenv("QIDS_TEST_API_KEY"))
	doc := []byte(fmt.Sprintf("go sdk qds %d", time.Now().UnixNano()))
	res, err := c.QDSSign(fmt.Sprintf("go-%d", time.Now().UnixNano()), doc, holders)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range holders {
		v, err := NewVerifierNode(nodes[name], tokens[name]).Verify(doc, res.Envelope)
		if err != nil || !v.Accepted {
			t.Fatalf("%s: %+v %v", name, v, err)
		}
	}
	v, err := NewVerifierNode(nodes[holders[0]], tokens[holders[0]]).Verify(append(doc, '!'), res.Envelope)
	if err != nil || v.Accepted {
		t.Fatalf("a changed document was accepted: %+v %v", v, err)
	}
}
