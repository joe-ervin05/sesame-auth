package sessions

import (
	"context"
	"net/http"
	"net/url"
)

func RequireSameOrigin(allowedOrigin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !VerifyRequestOrigin(r, allowedOrigin) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func VerifyRequestOrigin(r *http.Request, allowedOrigin string) bool {
	if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
		return true
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		referer := r.Header.Get("Referer")
		if referer == "" {
			return false
		}

		u, err := url.Parse(referer)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return false
		}

		origin = u.Scheme + "://" + u.Host
	}

	return origin == allowedOrigin
}

type contextKey string

const sessionContextKey contextKey = "session"
const userContextKey contextKey = "user"

func GetSession(ctx context.Context) *Session {
	session, _ := ctx.Value(sessionContextKey).(*Session)
	return session
}

func GetUser(ctx context.Context) *User {
	user, _ := ctx.Value(userContextKey).(*User)
	return user
}
