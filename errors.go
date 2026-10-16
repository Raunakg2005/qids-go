package qids

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Sentinel errors. Match them with errors.Is; use errors.As with *APIError
// for the status code, the gateway's message and the retry delay.
var (
	// ErrNoAPIKey is returned before any request is sent when the client has
	// no API key: every /api/v1 call on the gateway requires one.
	ErrNoAPIKey = errors.New("qids: API key is required")
	// ErrUnauthorized matches an HTTP 401: the API key is missing or invalid.
	ErrUnauthorized = errors.New("qids: unauthorized")
	// ErrForbidden matches an HTTP 403: the key's role lacks the permission.
	ErrForbidden = errors.New("qids: forbidden")
	// ErrRateLimited matches an HTTP 429. APIError.RetryAfter says how long
	// to wait.
	ErrRateLimited = errors.New("qids: rate limited")
)

// APIError is a non-2xx response from the gateway, with the fields of its
// JSON error body.
type APIError struct {
	StatusCode int
	// Op names the call that failed, e.g. "sign".
	Op string
	// ErrorText is the body's "error" field, e.g. "Rate limit exceeded".
	ErrorText string
	// Message is the body's "message" (or "detail") field.
	Message string
	// Reason is the body's "reason" field, when present.
	Reason string
	// RequiredPermission is set on a 403 that names the missing permission.
	RequiredPermission string
	// RetryAfter comes from the body's retry_after_seconds, else from the
	// Retry-After header; zero when the gateway gave neither.
	RetryAfter time.Duration
	// Body is the raw response body, at most 64 KiB.
	Body []byte
}

func (e *APIError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "qids: %s returned HTTP %d", e.Op, e.StatusCode)
	for _, s := range []string{e.ErrorText, e.Message, e.Reason} {
		if s != "" {
			b.WriteString(": ")
			b.WriteString(s)
		}
	}
	if e.RetryAfter > 0 {
		fmt.Fprintf(&b, " (retry after %s)", e.RetryAfter)
	}
	return b.String()
}

// Is makes errors.Is(err, ErrUnauthorized / ErrForbidden / ErrRateLimited)
// match on the status code.
func (e *APIError) Is(target error) bool {
	switch target {
	case ErrUnauthorized:
		return e.StatusCode == http.StatusUnauthorized
	case ErrForbidden:
		return e.StatusCode == http.StatusForbidden
	case ErrRateLimited:
		return e.StatusCode == http.StatusTooManyRequests
	}
	return false
}

// newAPIError reads a non-2xx response into an *APIError.
func newAPIError(op string, resp *http.Response) *APIError {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &APIError{StatusCode: resp.StatusCode, Op: op, Body: raw}
	var body struct {
		Error              string   `json:"error"`
		Message            string   `json:"message"`
		Detail             string   `json:"detail"`
		Reason             string   `json:"reason"`
		RequiredPermission string   `json:"required_permission"`
		RetryAfterSeconds  *float64 `json:"retry_after_seconds"`
	}
	if json.Unmarshal(raw, &body) == nil {
		e.ErrorText = body.Error
		e.Message = body.Message
		if e.Message == "" {
			e.Message = body.Detail
		}
		e.Reason = body.Reason
		e.RequiredPermission = body.RequiredPermission
		if body.RetryAfterSeconds != nil && *body.RetryAfterSeconds > 0 {
			e.RetryAfter = time.Duration(*body.RetryAfterSeconds * float64(time.Second))
		}
	}
	if e.RetryAfter == 0 {
		if s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
	}
	return e
}
