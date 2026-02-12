package ratelimit

import (
	"context"
	"net/http"
)

type Limiter interface {
	Consume(ctx context.Context, key string, cost int64) (bool, error)
}

func WithRateLimit(limiter Limiter, cost int64, keyFn func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ""
		if keyFn != nil {
			key = keyFn(r)
		}

		allowed, err := limiter.Consume(r.Context(), key, cost)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		if !allowed {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
