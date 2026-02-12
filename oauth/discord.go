package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type DiscordProviderConfig struct {
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

type DiscordProvider struct {
	*customOAuthProvider
}

var _ OAuthProvider = (*DiscordProvider)(nil)

func NewDiscordProvider(cfg DiscordProviderConfig) (*DiscordProvider, error) {
	if cfg.DisplayName == "" {
		cfg.DisplayName = "Discord"
	}

	authURL := strings.TrimSpace(cfg.AuthURL)
	if authURL == "" {
		authURL = "https://discord.com/oauth2/authorize"
	}

	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = "https://discord.com/api/oauth2/token"
	}

	apiBaseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBaseURL == "" {
		apiBaseURL = "https://discord.com/api/v10"
	}

	baseProvider, err := newCustomOAuthProvider(
		customOAuthProviderConfig{
			Name:         "discord",
			DisplayName:  cfg.DisplayName,
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			AuthURL:      authURL,
			TokenURL:     tokenURL,
			APIBaseURL:   apiBaseURL,
			HTTPClient:   cfg.HTTPClient,
		},
		&discordIdentityFetcher{},
		normalizeDiscordScopes,
	)
	if err != nil {
		return nil, err
	}

	return &DiscordProvider{customOAuthProvider: baseProvider}, nil
}

type discordIdentityFetcher struct{}

type discordUser struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

func (f *discordIdentityFetcher) FetchIdentity(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*OAuthIdentity, error) {
	user, err := f.fetchUser(ctx, tok, apiBaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
	}
	if strings.TrimSpace(user.ID) == "" {
		return nil, ErrOAuthAccountMissingUserID
	}

	email := strings.TrimSpace(user.Email)
	if email == "" {
		return nil, ErrOAuthEmailMissing
	}

	return &OAuthIdentity{
		ProviderUserID: user.ID,
		Email:          email,
		EmailVerified:  user.Verified,
	}, nil
}

func (f *discordIdentityFetcher) fetchUser(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*discordUser, error) {
	var user discordUser
	if err := getDiscordJSON(ctx, httpClient, tok.AccessToken, apiBaseURL+"/users/@me", &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func getDiscordJSON(ctx context.Context, httpClient *http.Client, accessToken, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sesame-oauth/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		return fmt.Errorf("discord api status %d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	err = json.NewDecoder(resp.Body).Decode(into)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func normalizeDiscordScopes(scopes []string) []string {
	base := []string{"identify", "email"}
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
