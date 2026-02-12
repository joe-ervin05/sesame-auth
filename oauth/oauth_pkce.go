package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const oauthStateCookieName = "oauth_state"

func ValidateOAuthStateSecret(secret string) error {
	if strings.TrimSpace(secret) == "" {
		return errors.New("missing oauth state secret")
	}
	return nil
}

func NewRandomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func SignOAuthState(secret, state, verifier string) (string, error) {
	if err := ValidateOAuthStateSecret(secret); err != nil {
		return "", err
	}
	payload := state + "." + verifier
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

func VerifyOAuthStateCookie(secret, raw string) (state string, verifier string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", "", errors.New("invalid oauth state cookie")
	}
	payload := parts[0] + "." + parts[1]
	if err := ValidateOAuthStateSecret(secret); err != nil {
		return "", "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[2]), []byte(expected)) {
		return "", "", errors.New("oauth state signature mismatch")
	}
	return parts[0], parts[1], nil
}

func SetOAuthStateCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})
}

func ReadOAuthStateCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		return "", fmt.Errorf("missing oauth state cookie: %w", err)
	}
	return c.Value, nil
}

func ClearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}
