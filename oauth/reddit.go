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

type RedditProviderConfig struct {
	DisplayName  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string

	PseudoEmailDomain string
	UserAgent         string

	AuthURL    string
	TokenURL   string
	APIBaseURL string
	HTTPClient *http.Client
}

type RedditProvider struct {
	*customOAuthProvider
}

var _ OAuthProvider = (*RedditProvider)(nil)

func NewRedditProvider(cfg RedditProviderConfig) (*RedditProvider, error) {
	if cfg.DisplayName == "" {
		cfg.DisplayName = "Reddit"
	}

	authURL := strings.TrimSpace(cfg.AuthURL)
	if authURL == "" {
		authURL = "https://www.reddit.com/api/v1/authorize"
	}

	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = "https://www.reddit.com/api/v1/access_token"
	}

	apiBaseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBaseURL == "" {
		apiBaseURL = "https://oauth.reddit.com/api/v1"
	}

	pseudoEmailDomain := strings.TrimSpace(strings.ToLower(cfg.PseudoEmailDomain))
	pseudoEmailDomain = strings.TrimPrefix(pseudoEmailDomain, "https://")
	pseudoEmailDomain = strings.TrimPrefix(pseudoEmailDomain, "http://")
	pseudoEmailDomain = strings.TrimSuffix(pseudoEmailDomain, "/")

	userAgent := strings.TrimSpace(cfg.UserAgent)
	if userAgent == "" {
		userAgent = "sesame-oauth/1.0"
	}

	baseProvider, err := newCustomOAuthProvider(
		customOAuthProviderConfig{
			Name:         "reddit",
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
		&redditIdentityFetcher{
			pseudoEmailDomain: pseudoEmailDomain,
			userAgent:         userAgent,
		},
		normalizeRedditScopes,
	)
	if err != nil {
		return nil, err
	}

	return &RedditProvider{customOAuthProvider: baseProvider}, nil
}

type redditIdentityFetcher struct {
	pseudoEmailDomain string
	userAgent         string
}

type redditMe struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Email            string `json:"email"`
	HasVerifiedEmail bool   `json:"has_verified_email"`
}

func (f *redditIdentityFetcher) FetchIdentity(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*OAuthIdentity, error) {
	me, err := f.fetchMe(ctx, tok, apiBaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
	}

	providerUserID := strings.TrimSpace(me.ID)
	if providerUserID == "" {
		providerUserID = strings.TrimSpace(me.Name)
	}
	if providerUserID == "" {
		return nil, ErrOAuthAccountMissingUserID
	}

	email := strings.TrimSpace(me.Email)
	emailVerified := me.HasVerifiedEmail

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

func (f *redditIdentityFetcher) fetchMe(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*redditMe, error) {
	var me redditMe
	if err := getRedditJSON(ctx, httpClient, tok.AccessToken, f.userAgent, apiBaseURL+"/me", &me); err != nil {
		return nil, err
	}
	return &me, nil
}

func (f *redditIdentityFetcher) pseudoEmail(me *redditMe) string {
	if me == nil {
		return ""
	}
	if f.pseudoEmailDomain == "" {
		return ""
	}

	local := strings.TrimSpace(strings.ToLower(me.Name))
	if local == "" {
		local = "user"
	}
	local = sanitizeLocalPart(local)
	if local == "" {
		local = "user"
	}

	id := strings.TrimSpace(strings.ToLower(me.ID))
	id = sanitizeLocalPart(id)
	if id != "" {
		local = local + "-" + id
	}

	return local + "@" + f.pseudoEmailDomain
}

func getRedditJSON(ctx context.Context, httpClient *http.Client, accessToken, userAgent, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		return fmt.Errorf("reddit api status %d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	err = json.NewDecoder(resp.Body).Decode(into)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func normalizeRedditScopes(scopes []string) []string {
	base := []string{"identity"}
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

func sanitizeLocalPart(s string) string {
	if s == "" {
		return ""
	}

	s = strings.ToLower(s)

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		if r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}

	return strings.Trim(b.String(), "._-")
}
