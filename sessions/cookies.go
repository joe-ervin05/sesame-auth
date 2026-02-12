package sessions

import (
	"net/http"
)

const SessionCookieName = "session"

type cookieOptions struct {
	Name     string
	Domain   string
	Path     string
	HttpOnly bool
	Secure   bool
	SameSite http.SameSite
}

func defaultCookieOptions() cookieOptions {
	return cookieOptions{
		Name:     SessionCookieName,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

func setSessionCookie(w http.ResponseWriter, token string, maxAgeSeconds int, opts cookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     opts.Name,
		Value:    token,
		Domain:   opts.Domain,
		Path:     opts.Path,
		MaxAge:   maxAgeSeconds,
		HttpOnly: opts.HttpOnly,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
	})
}

func clearSessionCookie(w http.ResponseWriter, opts cookieOptions) {
	http.SetCookie(w, &http.Cookie{
		Name:     opts.Name,
		Value:    "",
		Domain:   opts.Domain,
		Path:     opts.Path,
		MaxAge:   -1,
		HttpOnly: opts.HttpOnly,
		Secure:   opts.Secure,
		SameSite: opts.SameSite,
	})
}

func getSessionToken(r *http.Request, name string) string {
	if name == "" {
		name = SessionCookieName
	}

	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func GetSessionToken(r *http.Request) string {
	return getSessionToken(r, SessionCookieName)
}
