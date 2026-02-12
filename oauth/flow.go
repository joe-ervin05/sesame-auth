package oauth

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
)

type OAuthCallbackValidator interface {
	ValidateCallback(r *http.Request) error
}

func Start(stateSecret string, provider OAuthProvider) (signedState, url string, err error) {
	state, err := NewRandomURLSafe(32)
	if err != nil {
		return "", "", err
	}

	verifier, err := NewRandomURLSafe(48)
	if err != nil {
		return "", "", err
	}

	signedState, err = SignOAuthState(stateSecret, state, verifier)
	if err != nil {
		return "", "", err
	}

	challenge := PKCEChallenge(verifier)

	url, err = provider.AuthURL(state, challenge)
	if err != nil {
		return "", "", err
	}

	return signedState, url, err
}

func StartHTTP(w http.ResponseWriter, r *http.Request, stateSecret string, provider OAuthProvider) error {
	signedState, url, err := Start(stateSecret, provider)
	if err != nil {
		return err
	}

	SetOAuthStateCookie(w, signedState)
	http.Redirect(w, r, url, http.StatusFound)

	return nil
}

func HandleCallback(ctx context.Context, db *sql.DB, stateSecret string, provider OAuthProvider, rawStateCookie, callbackState, callbackErr, code string) (string, error) {
	expectedState, verifier, err := VerifyOAuthStateCookie(stateSecret, rawStateCookie)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthStateInvalid, err)
	}

	if callbackState != expectedState {
		return "", ErrOAuthStateMismatch
	}

	if callbackErr != "" {
		return "", fmt.Errorf("%w: %s", ErrOAuthProvider, callbackErr)
	}

	if code == "" {
		return "", ErrOAuthCodeMissing
	}

	identity, err := provider.ExchangeAndFetchIdentity(ctx, code, verifier)
	if err != nil {
		return "", err
	}

	return GetOrCreateUserFromOAuth(
		ctx,
		db,
		identity.Provider,
		identity.ProviderUserID,
		identity.Email,
		identity.EmailVerified,
	)
}

func HandleCallbackHTTP(w http.ResponseWriter, r *http.Request, db *sql.DB, stateSecret string, provider OAuthProvider) (string, error) {
	defer ClearOAuthStateCookie(w)

	if validator, ok := provider.(OAuthCallbackValidator); ok {
		if err := validator.ValidateCallback(r); err != nil {
			return "", fmt.Errorf("%w: %v", ErrOAuthCallbackInvalid, err)
		}
	}

	rawCookie, err := ReadOAuthStateCookie(r)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrOAuthStateMissing, err)
	}

	return HandleCallback(
		r.Context(),
		db,
		stateSecret,
		provider,
		rawCookie,
		r.URL.Query().Get("state"),
		r.URL.Query().Get("error"),
		r.URL.Query().Get("code"),
	)
}
