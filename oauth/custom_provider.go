package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type customOAuthProviderConfig struct {
	Name         string
	DisplayName  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	AuthURL    string
	TokenURL   string
	APIBaseURL string
	HTTPClient *http.Client
}

type customIdentityFetcher interface {
	FetchIdentity(ctx context.Context, token *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*OAuthIdentity, error)
}

type customOAuthProvider struct {
	name        string
	displayName string
	oauth2Cfg   *oauth2.Config
	apiBaseURL  string
	httpClient  *http.Client
	fetcher     customIdentityFetcher
}

func newCustomOAuthProvider(
	cfg customOAuthProviderConfig,
	fetcher customIdentityFetcher,
	normalizeScopes func([]string) []string,
) (*customOAuthProvider, error) {
	if cfg.Name == "" {
		return nil, errors.New("missing provider name")
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = strings.ToUpper(cfg.Name[:1]) + cfg.Name[1:]
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("missing %s client id", cfg.Name)
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("missing %s client secret", cfg.Name)
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("missing %s redirect url", cfg.Name)
	}
	if fetcher == nil {
		return nil, errors.New("missing custom identity fetcher")
	}

	authURL := strings.TrimSpace(cfg.AuthURL)
	if authURL == "" {
		return nil, fmt.Errorf("missing %s auth url", cfg.Name)
	}

	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		return nil, fmt.Errorf("missing %s token url", cfg.Name)
	}

	apiBaseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBaseURL == "" {
		return nil, fmt.Errorf("missing %s api base url", cfg.Name)
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	scopes := cfg.Scopes
	if normalizeScopes != nil {
		scopes = normalizeScopes(cfg.Scopes)
	}

	return &customOAuthProvider{
		name:        cfg.Name,
		displayName: cfg.DisplayName,
		oauth2Cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authURL,
				TokenURL: tokenURL,
			},
			Scopes: scopes,
		},
		apiBaseURL: apiBaseURL,
		httpClient: httpClient,
		fetcher:    fetcher,
	}, nil
}

func (p *customOAuthProvider) Name() string {
	return p.name
}

func (p *customOAuthProvider) DisplayName() string {
	return p.displayName
}

func (p *customOAuthProvider) AuthURL(state, codeChallenge string) (string, error) {
	if p == nil || p.oauth2Cfg == nil {
		return "", errors.New("custom oauth config missing")
	}

	url := p.oauth2Cfg.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return url, nil
}

func (p *customOAuthProvider) ExchangeAndFetchIdentity(ctx context.Context, code, codeVerifier string) (*OAuthIdentity, error) {
	if p == nil || p.oauth2Cfg == nil || p.apiBaseURL == "" || p.fetcher == nil {
		return nil, errors.New("custom oauth provider not initialized")
	}
	if code == "" {
		return nil, ErrOAuthCodeMissing
	}

	tok, err := p.oauth2Cfg.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthTokenExchange, err)
	}

	identity, err := p.fetcher.FetchIdentity(ctx, tok, p.apiBaseURL, p.httpClient)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, fmt.Errorf("%w: identity missing", ErrOAuthUserInfo)
	}
	if identity.Provider == "" {
		identity.Provider = p.name
	}

	return identity, nil
}
