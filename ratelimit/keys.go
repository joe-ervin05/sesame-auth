package ratelimit

import (
	"net"
	"net/http"

	"github.com/joe-ervin05/sesame-auth/sessions"
)

func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func UserIDFromSession(r *http.Request) string {
	session := sessions.GetSession(r.Context())
	if session == nil {
		return "anonymous"
	}
	return session.UserID
}
