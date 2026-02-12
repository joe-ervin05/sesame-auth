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

type TwitterProviderConfig struct {
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

type TwitterProvider struct {
	*customOAuthProvider
}

var _ OAuthProvider = (*TwitterProvider)(nil)

func NewTwitterProvider(cfg TwitterProviderConfig) (*TwitterProvider, error) {
	if cfg.DisplayName == "" {
		cfg.DisplayName = "Twitter"
	}

	authURL := strings.TrimSpace(cfg.AuthURL)
	if authURL == "" {
		authURL = "https://twitter.com/i/oauth2/authorize"
	}

	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = "https://api.twitter.com/2/oauth2/token"
	}

	apiBaseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBaseURL == "" {
		apiBaseURL = "https://api.twitter.com/2"
	}

	pseudoEmailDomain := strings.TrimSpace(strings.ToLower(cfg.PseudoEmailDomain))
	pseudoEmailDomain = strings.TrimPrefix(pseudoEmailDomain, "https://")
	pseudoEmailDomain = strings.TrimPrefix(pseudoEmailDomain, "http://")
	pseudoEmailDomain = strings.TrimSuffix(pseudoEmailDomain, "/")

	baseProvider, err := newCustomOAuthProvider(
		customOAuthProviderConfig{
			Name:         "twitter",
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
		&twitterIdentityFetcher{pseudoEmailDomain: pseudoEmailDomain},
		normalizeTwitterScopes,
	)
	if err != nil {
		return nil, err
	}

	return &TwitterProvider{customOAuthProvider: baseProvider}, nil
}

type twitterIdentityFetcher struct {
	pseudoEmailDomain string
}

type twitterMeResponse struct {
	Data twitterUser `json:"data"`
}

type twitterUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}

func (f *twitterIdentityFetcher) FetchIdentity(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*OAuthIdentity, error) {
	me, err := f.fetchMe(ctx, tok, apiBaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
	}

	providerUserID := strings.TrimSpace(me.Data.ID)
	if providerUserID == "" {
		return nil, ErrOAuthAccountMissingUserID
	}

	email := strings.TrimSpace(me.Data.Email)
	emailVerified := false
	if email != "" {
		emailVerified = true
	} else {
		email = f.pseudoEmail(me.Data)
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

func (f *twitterIdentityFetcher) fetchMe(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*twitterMeResponse, error) {
	var me twitterMeResponse
	endpoint := apiBaseURL + "/users/me?user.fields=id,name,username,email,verified"
	if err := getTwitterJSON(ctx, httpClient, tok.AccessToken, endpoint, &me); err != nil {
		return nil, err
	}
	return &me, nil
}

func (f *twitterIdentityFetcher) pseudoEmail(user twitterUser) string {
	if f.pseudoEmailDomain == "" {
		return ""
	}

	local := strings.TrimSpace(strings.ToLower(user.Username))
	if local == "" {
		local = strings.TrimSpace(strings.ToLower(user.Name))
	}
	if local == "" {
		local = "user"
	}
	local = sanitizeLocalPart(local)
	if local == "" {
		local = "user"
	}

	id := sanitizeLocalPart(strings.TrimSpace(strings.ToLower(user.ID)))
	if id != "" {
		local = local + "-" + id
	}

	return local + "@" + f.pseudoEmailDomain
}

func getTwitterJSON(ctx context.Context, httpClient *http.Client, accessToken, endpoint string, into any) error {
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
		return fmt.Errorf("twitter api status %d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	err = json.NewDecoder(resp.Body).Decode(into)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func normalizeTwitterScopes(scopes []string) []string {
	base := []string{"users.read"}
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
