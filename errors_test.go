package qids

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func gateway(t *testing.T, status int, header map[string]string, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRateLimitIsTypedWithRetryAfter(t *testing.T) {
	srv := gateway(t, 429, nil, `{"error":"Rate limit exceeded","limit_rpm":60,"retry_after_seconds":60}`)
	_, err := NewQIDSClientWithKey(srv.URL, "SAE_Alice", "sk_test_k").Sign("d1", []byte("x"), []string{"SAE_Bob"})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T", err)
	}
	if apiErr.StatusCode != 429 || apiErr.RetryAfter != 60*time.Second || apiErr.ErrorText != "Rate limit exceeded" {
		t.Fatalf("gateway error body lost: %+v", apiErr)
	}
	if errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrForbidden) {
		t.Fatal("429 must not match 401/403")
	}
}

func TestRetryAfterHeaderIsUsedWhenTheBodyHasNone(t *testing.T) {
	srv := gateway(t, 429, map[string]string{"Retry-After": "7"}, `{"error":"Too many links"}`)
	_, err := NewQIDSClientWithKey(srv.URL, "SAE_Alice", "sk_test_k").Verify("d1", []byte("x"), "ab", "k1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != 7*time.Second {
		t.Fatalf("Retry-After header ignored: %v", err)
	}
}

func TestUnauthorizedAndForbiddenAreDistinct(t *testing.T) {
	srv := gateway(t, 401, nil, `{"error":"Unauthorized","message":"Valid API key required."}`)
	_, err := NewQIDSClientWithKey(srv.URL, "SAE_Alice", "sk_test_bad").Sign("d1", []byte("x"), nil)
	if !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrForbidden) {
		t.Fatalf("want ErrUnauthorized only, got %v", err)
	}
	if !strings.Contains(err.Error(), "Valid API key required.") {
		t.Fatalf("gateway message dropped from %q", err.Error())
	}

	srv = gateway(t, 403, nil, `{"error":"Forbidden","message":"Role 'auditor' lacks the 'sign' permission.","required_permission":"sign"}`)
	_, err = NewQIDSClientWithKey(srv.URL, "SAE_Alice", "sk_test_k").Sign("d1", []byte("x"), nil)
	var apiErr *APIError
	if !errors.Is(err, ErrForbidden) || !errors.As(err, &apiErr) || apiErr.RequiredPermission != "sign" {
		t.Fatalf("want ErrForbidden naming the permission, got %v", err)
	}
}

func TestEmptyAPIKeyIsRejected(t *testing.T) {
	if _, err := NewClient("http://gw", "SAE_Alice", " "); !errors.Is(err, ErrNoAPIKey) {
		t.Fatalf("NewClient accepted an empty key: %v", err)
	}
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	c := NewQIDSClient(srv.URL, "SAE_Alice")
	if _, err := c.Sign("d1", []byte("x"), []string{"SAE_Bob"}); !errors.Is(err, ErrNoAPIKey) {
		t.Fatalf("keyless Sign: want ErrNoAPIKey, got %v", err)
	}
	if _, err := c.Verify("d1", []byte("x"), "ab", "k1"); !errors.Is(err, ErrNoAPIKey) {
		t.Fatalf("keyless Verify: want ErrNoAPIKey, got %v", err)
	}
	if hits != 0 {
		t.Fatalf("a keyless client sent %d requests", hits)
	}
}

func TestPrintingTheClientNeverShowsTheKey(t *testing.T) {
	const secret = "sk_live_DO_NOT_LEAK_123"
	c, err := NewClient("http://gw", "SAE_Alice", secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x"} {
		for _, v := range []interface{}{c, *c} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, secret) || strings.Contains(out, fmt.Sprintf("%x", secret)) {
				t.Fatalf("%s leaked the API key: %s", verb, out)
			}
		}
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), secret) {
		t.Fatalf("json.Marshal leaked the API key: %s", raw)
	}
	if !strings.Contains(fmt.Sprintf("%+v", c), "SAE_Alice") {
		t.Fatal("redacted form should still identify the client")
	}
}

func TestVerifyTagSendsRecipientAndReturnsThreat(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		_, _ = w.Write([]byte(`{"document_id":"d1","status":"REJECTED","is_valid":false,` +
			`"observed_error_rate":1.0,"threshold_error_rate":0.1111,"reason":"tag_mismatch",` +
			`"threat":"forgery","confidence":1.0,"evidence":{"submitted_tag":"ab"}}`))
	}))
	defer srv.Close()

	c := NewQIDSClientWithKey(srv.URL, "SAE_Alice", "sk_test_k")
	res, err := c.VerifyTag("d1", []byte("x"), SignatureTag{RecipientSAEID: "SAE_Carol", HashTag: "ab", KeyID: "k1"})
	if err != nil {
		t.Fatal(err)
	}
	if got["recipient_sae_id"] != "SAE_Carol" || got["hash_tag"] != "ab" || got["key_id"] != "k1" {
		t.Fatalf("verify request = %v", got)
	}
	if res.Threat != "forgery" || res.Confidence != 1.0 || res.Evidence["submitted_tag"] != "ab" {
		t.Fatalf("threat attribution dropped: %+v", res)
	}
}

func etsiKMS(t *testing.T, key string) *ETSI014Client {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{"key_ID": "k1", "key": key}}})
	srv := gateway(t, 200, nil, string(body))
	return NewETSI014Client(srv.URL, "SAE_Alice", "SAE_Bob")
}

func TestEncKeysRejectsWrongSizeAndUndecodableKeys(t *testing.T) {
	key48 := base64.StdEncoding.EncodeToString(make([]byte, 48))
	keys, err := etsiKMS(t, key48).GetEncKeys(1, 384)
	if err != nil || len(keys) != 1 || keys[0].SizeBits != 384 || len(keys[0].KeyBytes) != 48 {
		t.Fatalf("a correct 384-bit key failed: %v %+v", err, keys)
	}

	key13 := base64.StdEncoding.EncodeToString(make([]byte, 13))
	if keys, err := etsiKMS(t, key13).GetEncKeys(1, 100); err != nil || keys[0].SizeBits != 100 {
		t.Fatalf("a 100-bit key in 13 bytes failed: %v %+v", err, keys)
	}

	key32 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if keys, err := etsiKMS(t, key32).GetEncKeys(1, 384); err == nil {
		t.Fatalf("a 256-bit key was accepted as 384 bits: %+v", keys)
	}
	for _, bad := range []string{"!!not-a-key!!", ""} {
		if keys, err := etsiKMS(t, bad).GetEncKeys(1, 384); err == nil {
			t.Fatalf("undecodable key %q accepted: %+v", bad, keys)
		}
		if keys, err := etsiKMS(t, bad).GetDecKeys([]string{"k1"}); err == nil {
			t.Fatalf("undecodable dec key %q accepted: %+v", bad, keys)
		}
	}
}
