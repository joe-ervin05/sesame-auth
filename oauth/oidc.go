package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type OIDCProviderConfig struct {
	Name         string
	DisplayName  string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

type OIDCProvider struct {
	name        string
	displayName string
	oauth2Cfg   *oauth2.Config
	oidcCfg     *oidc.Config
	oidcProv    *oidc.Provider
}

var _ OAuthProvider = (*OIDCProvider)(nil)

func NewOIDCProvider(ctx context.Context, cfg OIDCProviderConfig) (*OIDCProvider, error) {
	if cfg.Name == "" {
		return nil, errors.New("missing oidc provider name")
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = cfg.Name
	}
	if cfg.IssuerURL == "" {
		return nil, errors.New("missing oidc issuer url")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("missing oidc client id")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("missing oidc client secret")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("missing oidc redirect url")
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	scopes := normalizeOIDCScopes(cfg.Scopes)

	return &OIDCProvider{
		name:        cfg.Name,
		displayName: cfg.DisplayName,
		oauth2Cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		oidcCfg: &oidc.Config{
			ClientID: cfg.ClientID,
		},
		oidcProv: provider,
	}, nil
}

func (p *OIDCProvider) Name() string {
	return p.name
}

func (p *OIDCProvider) DisplayName() string {
	return p.displayName
}

func (p *OIDCProvider) AuthURL(state, codeChallenge string) (string, error) {
	if p == nil || p.oauth2Cfg == nil {
		return "", errors.New("oidc oauth config missing")
	}

	url := p.oauth2Cfg.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	return url, nil
}

func (p *OIDCProvider) ExchangeAndFetchIdentity(ctx context.Context, code, codeVerifier string) (*OAuthIdentity, error) {
	if p == nil || p.oauth2Cfg == nil || p.oidcProv == nil || p.oidcCfg == nil {
		return nil, errors.New("oidc provider not initialized")
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

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, ErrOAuthIDTokenMissing
	}

	idToken, err := p.oidcProv.Verifier(p.oidcCfg).Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthIDTokenInvalid, err)
	}

	claims := struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthIDTokenInvalid, err)
	}

	if claims.Sub == "" {
		return nil, ErrOAuthAccountMissingUserID
	}

	if claims.Email == "" {
		userInfo, err := p.oidcProv.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
		}

		infoClaims := struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}{}
		if err := userInfo.Claims(&infoClaims); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
		}

		if infoClaims.Sub != "" && infoClaims.Sub != claims.Sub {
			return nil, fmt.Errorf("%w: sub mismatch", ErrOAuthUserInfo)
		}

		if infoClaims.Email != "" {
			claims.Email = infoClaims.Email
			claims.EmailVerified = infoClaims.EmailVerified
		}
	}

	return &OAuthIdentity{
		Provider:       p.name,
		ProviderUserID: claims.Sub,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
	}, nil
}

func normalizeOIDCScopes(scopes []string) []string {
	base := []string{"openid", "email", "profile"}

	seen := make(map[string]struct{}, len(base)+len(scopes))
	normalized := make([]string, 0, len(base)+len(scopes))

	for _, scope := range base {
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}

	for _, scope := range scopes {
		s := strings.TrimSpace(scope)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		normalized = append(normalized, s)
	}

	return normalized
}
