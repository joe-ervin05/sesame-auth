package oauth

import (
	"context"
	"errors"
	"net/url"
	"sort"
	"strings"
)

type OAuthIdentity struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
}

type OAuthProvider interface {
	Name() string
	DisplayName() string
	AuthURL(state, codeChallenge string) (string, error)
	ExchangeAndFetchIdentity(ctx context.Context, code, codeVerifier string) (*OAuthIdentity, error)
}

type OAuthProviderMeta struct {
	Name        string
	DisplayName string
	LoginPath   string
}

func buildOAuthCallbackURL(appBaseURL, providerName string) (string, error) {
	parsedBaseURL, err := url.Parse(appBaseURL)
	if err != nil || parsedBaseURL.Scheme == "" || parsedBaseURL.Host == "" {
		return "", errors.New("invalid APP_BASE_URL")
	}

	trimmedPath := strings.TrimRight(parsedBaseURL.Path, "/")
	parsedBaseURL.Path = trimmedPath + "/oauth/" + providerName + "/callback"
	parsedBaseURL.RawQuery = ""
	parsedBaseURL.Fragment = ""

	return parsedBaseURL.String(), nil
}

func OAuthProviderMetadata(providers map[string]OAuthProvider) []OAuthProviderMeta {
	meta := make([]OAuthProviderMeta, 0, len(providers))
	for name, provider := range providers {
		meta = append(meta, OAuthProviderMeta{
			Name:        name,
			DisplayName: provider.DisplayName(),
			LoginPath:   "/oauth/" + name,
		})
	}

	sort.Slice(meta, func(i, j int) bool {
		return meta[i].DisplayName < meta[j].DisplayName
	})

	return meta
}
