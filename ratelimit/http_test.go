package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeLimiter struct {
	allow bool
	err   error
}

func (f fakeLimiter) Consume(ctx context.Context, key string, cost int64) (bool, error) {
	return f.allow, f.err
}

func TestWithRateLimitDenied(t *testing.T) {
	h := WithRateLimit(fakeLimiter{allow: false}, 1, func(r *http.Request) string { return "k" }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}

func TestWithRateLimitAllowed(t *testing.T) {
	h := WithRateLimit(fakeLimiter{allow: true}, 1, func(r *http.Request) string { return "k" }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
}
