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

type SpotifyProviderConfig struct {
	DisplayName  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	PseudoEmailDomain string

	AuthURL    string
	TokenURL   string
	APIBaseURL string
	HTTPClient *http.Client
}

type SpotifyProvider struct {
	*customOAuthProvider
}

var _ OAuthProvider = (*SpotifyProvider)(nil)

func NewSpotifyProvider(cfg SpotifyProviderConfig) (*SpotifyProvider, error) {
	if cfg.DisplayName == "" {
		cfg.DisplayName = "Spotify"
	}

	authURL := strings.TrimSpace(cfg.AuthURL)
	if authURL == "" {
		authURL = "https://accounts.spotify.com/authorize"
	}

	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = "https://accounts.spotify.com/api/token"
	}

	apiBaseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBaseURL == "" {
		apiBaseURL = "https://api.spotify.com/v1"
	}

	pseudoEmailDomain := strings.TrimSpace(strings.ToLower(cfg.PseudoEmailDomain))
	pseudoEmailDomain = strings.TrimPrefix(pseudoEmailDomain, "https://")
	pseudoEmailDomain = strings.TrimPrefix(pseudoEmailDomain, "http://")
	pseudoEmailDomain = strings.TrimSuffix(pseudoEmailDomain, "/")

	baseProvider, err := newCustomOAuthProvider(
		customOAuthProviderConfig{
			Name:         "spotify",
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
		&spotifyIdentityFetcher{pseudoEmailDomain: pseudoEmailDomain},
		normalizeSpotifyScopes,
	)
	if err != nil {
		return nil, err
	}

	return &SpotifyProvider{customOAuthProvider: baseProvider}, nil
}

type spotifyIdentityFetcher struct {
	pseudoEmailDomain string
}

type spotifyMe struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (f *spotifyIdentityFetcher) FetchIdentity(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*OAuthIdentity, error) {
	me, err := f.fetchMe(ctx, tok, apiBaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
	}

	providerUserID := strings.TrimSpace(me.ID)
	if providerUserID == "" {
		return nil, ErrOAuthAccountMissingUserID
	}

	email := strings.TrimSpace(me.Email)
	emailVerified := true
	if email == "" {
		email = f.pseudoEmail(me)
		emailVerified = false
	}

	if email == "" {
		return nil, ErrOAuthEmailMissing
	}

	return &OAuthIdentity{
		ProviderUserID: providerUserID,
		Email:          email,
		EmailVerified:  emailVerified,
	}, nil
}

func (f *spotifyIdentityFetcher) fetchMe(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*spotifyMe, error) {
	var me spotifyMe
	if err := getSpotifyJSON(ctx, httpClient, tok.AccessToken, apiBaseURL+"/me", &me); err != nil {
		return nil, err
	}
	return &me, nil
}

func (f *spotifyIdentityFetcher) pseudoEmail(me *spotifyMe) string {
	if me == nil || f.pseudoEmailDomain == "" {
		return ""
	}

	local := sanitizeLocalPart(strings.ToLower(strings.TrimSpace(me.ID)))
	if local == "" {
		local = "spotify-user"
	}

	return local + "@" + f.pseudoEmailDomain
}

func getSpotifyJSON(ctx context.Context, httpClient *http.Client, accessToken, endpoint string, into any) error {
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
		return fmt.Errorf("spotify api status %d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	err = json.NewDecoder(resp.Body).Decode(into)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func normalizeSpotifyScopes(scopes []string) []string {
	base := []string{"user-read-email"}
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
