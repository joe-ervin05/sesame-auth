package oauth

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
)

type ClientConfig struct {
	DB          *sql.DB
	StateSecret string
	Providers   map[string]OAuthProvider
}

type Client struct {
	db          *sql.DB
	stateSecret string
	providers   map[string]OAuthProvider
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.DB == nil {
		return nil, errors.New("oauth client requires db")
	}
	if err := ValidateOAuthStateSecret(cfg.StateSecret); err != nil {
		return nil, err
	}
	if len(cfg.Providers) == 0 {
		return nil, errors.New("oauth client requires at least one provider")
	}

	providers := make(map[string]OAuthProvider, len(cfg.Providers))
	for name, provider := range cfg.Providers {
		if provider == nil {
			return nil, fmt.Errorf("oauth provider %q is nil", name)
		}
		providers[name] = provider
	}

	return &Client{
		db:          cfg.DB,
		stateSecret: cfg.StateSecret,
		providers:   providers,
	}, nil
}

func (c *Client) ProviderMetadata() []OAuthProviderMeta {
	return OAuthProviderMetadata(c.providers)
}

func (c *Client) StartHTTP(w http.ResponseWriter, r *http.Request, providerName string) error {
	provider, ok := c.providers[providerName]
	if !ok {
		return ErrOAuthProviderNotFound
	}

	signedState, url, err := Start(c.stateSecret, provider)
	if err != nil {
		return err
	}

	SetOAuthStateCookie(w, signedState)
	http.Redirect(w, r, url, http.StatusFound)

	return nil
}

func (c *Client) HandleCallbackHTTP(w http.ResponseWriter, r *http.Request, providerName string) (string, error) {
	provider, ok := c.providers[providerName]
	if !ok {
		return "", ErrOAuthProviderNotFound
	}

	return HandleCallbackHTTP(w, r, c.db, c.stateSecret, provider)
}
