package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

type GitHubProviderConfig struct {
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

type GitHubProvider struct {
	*customOAuthProvider
}

var _ OAuthProvider = (*GitHubProvider)(nil)

func NewGitHubProvider(cfg GitHubProviderConfig) (*GitHubProvider, error) {
	if cfg.DisplayName == "" {
		cfg.DisplayName = "GitHub"
	}

	authURL := strings.TrimSpace(cfg.AuthURL)
	if authURL == "" {
		authURL = "https://github.com/login/oauth/authorize"
	}

	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = "https://github.com/login/oauth/access_token"
	}

	apiBaseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBaseURL == "" {
		apiBaseURL = "https://api.github.com"
	}

	baseProvider, err := newCustomOAuthProvider(
		customOAuthProviderConfig{
			Name:         "github",
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
		&githubIdentityFetcher{},
		normalizeGitHubScopes,
	)
	if err != nil {
		return nil, err
	}

	return &GitHubProvider{customOAuthProvider: baseProvider}, nil
}

type githubUser struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

type githubIdentityFetcher struct{}

func (f *githubIdentityFetcher) FetchIdentity(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*OAuthIdentity, error) {
	user, err := f.fetchUser(ctx, tok, apiBaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
	}
	if user.ID <= 0 {
		return nil, ErrOAuthAccountMissingUserID
	}

	email, emailVerified, err := f.resolveEmail(ctx, tok, apiBaseURL, httpClient, user.Email)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
	}
	if strings.TrimSpace(email) == "" {
		return nil, ErrOAuthEmailMissing
	}

	return &OAuthIdentity{
		ProviderUserID: fmt.Sprintf("%d", user.ID),
		Email:          email,
		EmailVerified:  emailVerified,
	}, nil
}

func (f *githubIdentityFetcher) fetchUser(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*githubUser, error) {
	var user githubUser
	if err := getGitHubJSON(ctx, httpClient, tok.AccessToken, apiBaseURL+"/user", &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (f *githubIdentityFetcher) fetchEmails(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) ([]githubEmail, error) {
	var emails []githubEmail
	if err := getGitHubJSON(ctx, httpClient, tok.AccessToken, apiBaseURL+"/user/emails", &emails); err != nil {
		return nil, err
	}
	return emails, nil
}

func (f *githubIdentityFetcher) resolveEmail(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client, publicEmail string) (string, bool, error) {
	emails, err := f.fetchEmails(ctx, tok, apiBaseURL, httpClient)
	if err != nil {
		fallback := strings.TrimSpace(publicEmail)
		if fallback == "" {
			return "", false, fmt.Errorf("github emails fetch failed: %w", err)
		}
		return fallback, false, nil
	}

	var selected *githubEmail
	for i := range emails {
		e := emails[i]
		e.Email = strings.TrimSpace(e.Email)
		if e.Email == "" {
			continue
		}

		if e.Primary && e.Verified {
			return e.Email, true, nil
		}

		if selected == nil {
			selected = &e
			continue
		}

		if !selected.Primary && e.Primary {
			selected = &e
			continue
		}

		if !selected.Verified && e.Verified {
			selected = &e
		}
	}

	if selected != nil {
		return selected.Email, selected.Verified, nil
	}

	fallback := strings.TrimSpace(publicEmail)
	if fallback == "" {
		return "", false, nil
	}

	return fallback, false, nil
}

func getGitHubJSON(ctx context.Context, httpClient *http.Client, accessToken, endpoint string, into any) error {
	authHeaders := []string{"token " + accessToken, "Bearer " + accessToken}
	var lastErr error

	for _, authHeader := range authHeaders {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", authHeader)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "sesame-oauth/1.0")

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf(
				"github api status %d (oauth_scopes=%q accepted_scopes=%q body=%q)",
				resp.StatusCode,
				resp.Header.Get("X-OAuth-Scopes"),
				resp.Header.Get("X-Accepted-OAuth-Scopes"),
				strings.TrimSpace(string(body)),
			)
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				continue
			}
			return lastErr
		}

		err = json.NewDecoder(resp.Body).Decode(into)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}

		return nil
	}

	if lastErr != nil {
		return lastErr
	}

	return errors.New("github api request failed")
}

func normalizeGitHubScopes(scopes []string) []string {
	base := []string{"read:user", "user:email"}
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
