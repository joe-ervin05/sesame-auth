package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
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

func OAuthProvidersFromEnv() (map[string]OAuthProvider, error) {
	providers := map[string]OAuthProvider{}

	spotifyProvider, err := spotifyProviderFromEnv()
	if err != nil {
		return nil, err
	}
	if spotifyProvider != nil {
		providers[spotifyProvider.Name()] = spotifyProvider
	}

	twitterProvider, err := twitterProviderFromEnv()
	if err != nil {
		return nil, err
	}
	if twitterProvider != nil {
		providers[twitterProvider.Name()] = twitterProvider
	}

	redditProvider, err := redditProviderFromEnv()
	if err != nil {
		return nil, err
	}
	if redditProvider != nil {
		providers[redditProvider.Name()] = redditProvider
	}

	shopifyProvider, err := shopifyProviderFromEnv()
	if err != nil {
		return nil, err
	}
	if shopifyProvider != nil {
		providers[shopifyProvider.Name()] = shopifyProvider
	}

	discordProvider, err := discordProviderFromEnv()
	if err != nil {
		return nil, err
	}
	if discordProvider != nil {
		providers[discordProvider.Name()] = discordProvider
	}

	githubProvider, err := githubProviderFromEnv()
	if err != nil {
		return nil, err
	}
	if githubProvider != nil {
		providers[githubProvider.Name()] = githubProvider
	}

	oidcProviders, err := oidcProvidersFromEnv(context.Background())
	if err != nil {
		return nil, err
	}
	for name, provider := range oidcProviders {
		if _, exists := providers[name]; exists {
			return nil, fmt.Errorf("duplicate oauth provider name: %s", name)
		}
		providers[name] = provider
	}

	if len(providers) == 0 {
		return nil, errors.New("no oauth providers configured")
	}

	return providers, nil
}

func spotifyProviderFromEnv() (OAuthProvider, error) {
	clientID := strings.TrimSpace(os.Getenv("OAUTH_SPOTIFY_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_SPOTIFY_CLIENT_SECRET"))
	displayName := strings.TrimSpace(os.Getenv("OAUTH_SPOTIFY_DISPLAY_NAME"))
	scopesRaw := strings.TrimSpace(os.Getenv("OAUTH_SPOTIFY_SCOPES"))
	pseudoEmailDomain := strings.TrimSpace(os.Getenv("OAUTH_SPOTIFY_PSEUDO_EMAIL_DOMAIN"))
	redirectURLOverride := strings.TrimSpace(os.Getenv("OAUTH_SPOTIFY_REDIRECT_URL"))

	if clientID == "" && clientSecret == "" {
		return nil, nil
	}

	if clientID == "" {
		return nil, errors.New("missing OAUTH_SPOTIFY_CLIENT_ID")
	}
	if clientSecret == "" {
		return nil, errors.New("missing OAUTH_SPOTIFY_CLIENT_SECRET")
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		return nil, errors.New("missing APP_BASE_URL")
	}

	redirectURL := redirectURLOverride
	if redirectURL == "" {
		var err error
		redirectURL, err = buildOAuthCallbackURL(appBaseURL, "spotify")
		if err != nil {
			return nil, fmt.Errorf("provider spotify: %w", err)
		}
	}

	var extraScopes []string
	if scopesRaw != "" {
		extraScopes = strings.Split(scopesRaw, ",")
	}

	provider, err := NewSpotifyProvider(SpotifyProviderConfig{
		DisplayName:       displayName,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		RedirectURL:       redirectURL,
		Scopes:            extraScopes,
		PseudoEmailDomain: pseudoEmailDomain,
	})
	if err != nil {
		return nil, fmt.Errorf("provider spotify: %w", err)
	}

	return provider, nil
}

func twitterProviderFromEnv() (OAuthProvider, error) {
	clientID := strings.TrimSpace(os.Getenv("OAUTH_TWITTER_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_TWITTER_CLIENT_SECRET"))
	displayName := strings.TrimSpace(os.Getenv("OAUTH_TWITTER_DISPLAY_NAME"))
	scopesRaw := strings.TrimSpace(os.Getenv("OAUTH_TWITTER_SCOPES"))
	pseudoEmailDomain := strings.TrimSpace(os.Getenv("OAUTH_TWITTER_PSEUDO_EMAIL_DOMAIN"))

	if clientID == "" && clientSecret == "" {
		return nil, nil
	}

	if clientID == "" {
		return nil, errors.New("missing OAUTH_TWITTER_CLIENT_ID")
	}
	if clientSecret == "" {
		return nil, errors.New("missing OAUTH_TWITTER_CLIENT_SECRET")
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		return nil, errors.New("missing APP_BASE_URL")
	}

	redirectURL, err := buildOAuthCallbackURL(appBaseURL, "twitter")
	if err != nil {
		return nil, fmt.Errorf("provider twitter: %w", err)
	}

	var extraScopes []string
	if scopesRaw != "" {
		extraScopes = strings.Split(scopesRaw, ",")
	}

	provider, err := NewTwitterProvider(TwitterProviderConfig{
		DisplayName:       displayName,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		RedirectURL:       redirectURL,
		Scopes:            extraScopes,
		PseudoEmailDomain: pseudoEmailDomain,
	})
	if err != nil {
		return nil, fmt.Errorf("provider twitter: %w", err)
	}

	return provider, nil
}

func redditProviderFromEnv() (OAuthProvider, error) {
	clientID := strings.TrimSpace(os.Getenv("OAUTH_REDDIT_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_REDDIT_CLIENT_SECRET"))
	displayName := strings.TrimSpace(os.Getenv("OAUTH_REDDIT_DISPLAY_NAME"))
	scopesRaw := strings.TrimSpace(os.Getenv("OAUTH_REDDIT_SCOPES"))
	pseudoEmailDomain := strings.TrimSpace(os.Getenv("OAUTH_REDDIT_PSEUDO_EMAIL_DOMAIN"))
	userAgent := strings.TrimSpace(os.Getenv("OAUTH_REDDIT_USER_AGENT"))

	if clientID == "" && clientSecret == "" {
		return nil, nil
	}

	if clientID == "" {
		return nil, errors.New("missing OAUTH_REDDIT_CLIENT_ID")
	}
	if clientSecret == "" {
		return nil, errors.New("missing OAUTH_REDDIT_CLIENT_SECRET")
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		return nil, errors.New("missing APP_BASE_URL")
	}

	redirectURL, err := buildOAuthCallbackURL(appBaseURL, "reddit")
	if err != nil {
		return nil, fmt.Errorf("provider reddit: %w", err)
	}

	var extraScopes []string
	if scopesRaw != "" {
		extraScopes = strings.Split(scopesRaw, ",")
	}

	provider, err := NewRedditProvider(RedditProviderConfig{
		DisplayName:       displayName,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		RedirectURL:       redirectURL,
		Scopes:            extraScopes,
		PseudoEmailDomain: pseudoEmailDomain,
		UserAgent:         userAgent,
	})
	if err != nil {
		return nil, fmt.Errorf("provider reddit: %w", err)
	}

	return provider, nil
}

func shopifyProviderFromEnv() (OAuthProvider, error) {
	clientID := strings.TrimSpace(os.Getenv("OAUTH_SHOPIFY_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_SHOPIFY_CLIENT_SECRET"))
	displayName := strings.TrimSpace(os.Getenv("OAUTH_SHOPIFY_DISPLAY_NAME"))
	scopesRaw := strings.TrimSpace(os.Getenv("OAUTH_SHOPIFY_SCOPES"))
	shopDomain := strings.TrimSpace(os.Getenv("OAUTH_SHOPIFY_SHOP_DOMAIN"))

	if clientID == "" && clientSecret == "" {
		return nil, nil
	}

	if clientID == "" {
		return nil, errors.New("missing OAUTH_SHOPIFY_CLIENT_ID")
	}
	if clientSecret == "" {
		return nil, errors.New("missing OAUTH_SHOPIFY_CLIENT_SECRET")
	}
	if shopDomain == "" {
		return nil, errors.New("missing OAUTH_SHOPIFY_SHOP_DOMAIN")
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		return nil, errors.New("missing APP_BASE_URL")
	}

	redirectURL, err := buildOAuthCallbackURL(appBaseURL, "shopify")
	if err != nil {
		return nil, fmt.Errorf("provider shopify: %w", err)
	}

	var extraScopes []string
	if scopesRaw != "" {
		extraScopes = strings.Split(scopesRaw, ",")
	}

	provider, err := NewShopifyProvider(ShopifyProviderConfig{
		DisplayName:  displayName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       extraScopes,
		ShopDomain:   shopDomain,
	})
	if err != nil {
		return nil, fmt.Errorf("provider shopify: %w", err)
	}

	return provider, nil
}

func discordProviderFromEnv() (OAuthProvider, error) {
	clientID := strings.TrimSpace(os.Getenv("OAUTH_DISCORD_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_DISCORD_CLIENT_SECRET"))
	displayName := strings.TrimSpace(os.Getenv("OAUTH_DISCORD_DISPLAY_NAME"))
	scopesRaw := strings.TrimSpace(os.Getenv("OAUTH_DISCORD_SCOPES"))

	if clientID == "" && clientSecret == "" {
		return nil, nil
	}

	if clientID == "" {
		return nil, errors.New("missing OAUTH_DISCORD_CLIENT_ID")
	}
	if clientSecret == "" {
		return nil, errors.New("missing OAUTH_DISCORD_CLIENT_SECRET")
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		return nil, errors.New("missing APP_BASE_URL")
	}

	redirectURL, err := buildOAuthCallbackURL(appBaseURL, "discord")
	if err != nil {
		return nil, fmt.Errorf("provider discord: %w", err)
	}

	var extraScopes []string
	if scopesRaw != "" {
		extraScopes = strings.Split(scopesRaw, ",")
	}

	provider, err := NewDiscordProvider(DiscordProviderConfig{
		DisplayName:  displayName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       extraScopes,
	})
	if err != nil {
		return nil, fmt.Errorf("provider discord: %w", err)
	}

	return provider, nil
}

func githubProviderFromEnv() (OAuthProvider, error) {
	clientID := strings.TrimSpace(os.Getenv("OAUTH_GITHUB_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("OAUTH_GITHUB_CLIENT_SECRET"))
	displayName := strings.TrimSpace(os.Getenv("OAUTH_GITHUB_DISPLAY_NAME"))
	scopesRaw := strings.TrimSpace(os.Getenv("OAUTH_GITHUB_SCOPES"))

	if clientID == "" && clientSecret == "" {
		return nil, nil
	}

	if clientID == "" {
		return nil, errors.New("missing OAUTH_GITHUB_CLIENT_ID")
	}
	if clientSecret == "" {
		return nil, errors.New("missing OAUTH_GITHUB_CLIENT_SECRET")
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		return nil, errors.New("missing APP_BASE_URL")
	}

	redirectURL, err := buildOAuthCallbackURL(appBaseURL, "github")
	if err != nil {
		return nil, fmt.Errorf("provider github: %w", err)
	}

	var extraScopes []string
	if scopesRaw != "" {
		extraScopes = strings.Split(scopesRaw, ",")
	}

	provider, err := NewGitHubProvider(GitHubProviderConfig{
		DisplayName:  displayName,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       extraScopes,
	})
	if err != nil {
		return nil, fmt.Errorf("provider github: %w", err)
	}

	return provider, nil
}

func oidcProvidersFromEnv(ctx context.Context) (map[string]OAuthProvider, error) {
	providerList := strings.TrimSpace(os.Getenv("OAUTH_OIDC_PROVIDERS"))
	if providerList == "" {
		return map[string]OAuthProvider{}, nil
	}

	appBaseURL := os.Getenv("APP_BASE_URL")
	if appBaseURL == "" {
		return nil, errors.New("missing APP_BASE_URL")
	}

	providerNames := strings.Split(providerList, ",")
	providers := make(map[string]OAuthProvider, len(providerNames))
	for _, rawName := range providerNames {
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" {
			continue
		}

		envPrefix := "OAUTH_OIDC_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
		issuerURL := strings.TrimSpace(os.Getenv(envPrefix + "ISSUER_URL"))
		clientID := strings.TrimSpace(os.Getenv(envPrefix + "CLIENT_ID"))
		clientSecret := strings.TrimSpace(os.Getenv(envPrefix + "CLIENT_SECRET"))
		displayName := strings.TrimSpace(os.Getenv(envPrefix + "DISPLAY_NAME"))
		scopesRaw := strings.TrimSpace(os.Getenv(envPrefix + "SCOPES"))

		if displayName == "" {
			displayName = strings.ToUpper(name[:1]) + name[1:]
		}

		redirectURL, err := buildOAuthCallbackURL(appBaseURL, name)
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", name, err)
		}

		var extraScopes []string
		if scopesRaw != "" {
			extraScopes = strings.Split(scopesRaw, ",")
		}

		provider, err := NewOIDCProvider(ctx, OIDCProviderConfig{
			Name:         name,
			DisplayName:  displayName,
			IssuerURL:    issuerURL,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       extraScopes,
		})
		if err != nil {
			return nil, fmt.Errorf("provider %s: %w", name, err)
		}

		providers[name] = provider
	}

	return providers, nil
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
