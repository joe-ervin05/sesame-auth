package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

type ShopifyProviderConfig struct {
	DisplayName  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	ShopDomain   string

	AuthURL    string
	TokenURL   string
	APIBaseURL string
	HTTPClient *http.Client
}

type ShopifyProvider struct {
	*customOAuthProvider
	shopDomain   string
	clientSecret string
}

var _ OAuthProvider = (*ShopifyProvider)(nil)
var _ OAuthCallbackValidator = (*ShopifyProvider)(nil)

func NewShopifyProvider(cfg ShopifyProviderConfig) (*ShopifyProvider, error) {
	if cfg.DisplayName == "" {
		cfg.DisplayName = "Shopify"
	}

	shopDomain, err := normalizeShopifyShopDomain(cfg.ShopDomain)
	if err != nil {
		return nil, err
	}

	authURL := strings.TrimSpace(cfg.AuthURL)
	if authURL == "" {
		authURL = "https://" + shopDomain + "/admin/oauth/authorize"
	}

	tokenURL := strings.TrimSpace(cfg.TokenURL)
	if tokenURL == "" {
		tokenURL = "https://" + shopDomain + "/admin/oauth/access_token"
	}

	apiBaseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if apiBaseURL == "" {
		apiBaseURL = "https://" + shopDomain + "/admin/api/2025-01"
	}

	baseProvider, err := newCustomOAuthProvider(
		customOAuthProviderConfig{
			Name:         "shopify",
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
		&shopifyIdentityFetcher{},
		normalizeShopifyScopes,
	)
	if err != nil {
		return nil, err
	}

	return &ShopifyProvider{
		customOAuthProvider: baseProvider,
		shopDomain:          shopDomain,
		clientSecret:        cfg.ClientSecret,
	}, nil
}

func (p *ShopifyProvider) ValidateCallback(r *http.Request) error {
	if p == nil {
		return errors.New("shopify provider not initialized")
	}

	receivedHMAC := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("hmac")))
	if receivedHMAC == "" {
		return errors.New("shopify callback hmac missing")
	}

	callbackShop, err := normalizeShopifyShopDomain(r.URL.Query().Get("shop"))
	if err != nil {
		return fmt.Errorf("invalid shop in callback: %w", err)
	}
	if callbackShop != p.shopDomain {
		return fmt.Errorf("shop mismatch in callback: %s", callbackShop)
	}

	payload := canonicalShopifyCallbackQuery(r.URL.RawQuery)
	if payload == "" {
		return errors.New("shopify callback query payload empty")
	}

	mac := hmac.New(sha256.New, []byte(p.clientSecret))
	_, _ = mac.Write([]byte(payload))
	expectedHMAC := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(receivedHMAC), []byte(expectedHMAC)) {
		return errors.New("shopify callback hmac mismatch")
	}

	return nil
}

type shopifyIdentityFetcher struct{}

type shopifyShopResponse struct {
	Shop shopifyShop `json:"shop"`
}

type shopifyShop struct {
	ID              int64  `json:"id"`
	Email           string `json:"email"`
	Domain          string `json:"domain"`
	MyshopifyDomain string `json:"myshopify_domain"`
}

func (f *shopifyIdentityFetcher) FetchIdentity(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*OAuthIdentity, error) {
	shopResp, err := f.fetchShop(ctx, tok, apiBaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOAuthUserInfo, err)
	}

	providerUserID := strings.TrimSpace(shopResp.Shop.MyshopifyDomain)
	if providerUserID == "" {
		if shopResp.Shop.ID <= 0 {
			return nil, ErrOAuthAccountMissingUserID
		}
		providerUserID = strconv.FormatInt(shopResp.Shop.ID, 10)
	}

	email := strings.TrimSpace(shopResp.Shop.Email)
	if email == "" {
		return nil, ErrOAuthEmailMissing
	}

	return &OAuthIdentity{
		ProviderUserID: providerUserID,
		Email:          email,
		EmailVerified:  true,
	}, nil
}

func (f *shopifyIdentityFetcher) fetchShop(ctx context.Context, tok *oauth2.Token, apiBaseURL string, httpClient *http.Client) (*shopifyShopResponse, error) {
	var resp shopifyShopResponse
	if err := getShopifyJSON(ctx, httpClient, tok.AccessToken, apiBaseURL+"/shop.json", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func getShopifyJSON(ctx context.Context, httpClient *http.Client, accessToken, endpoint string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Shopify-Access-Token", accessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sesame-oauth/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		return fmt.Errorf("shopify api status %d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	err = json.NewDecoder(resp.Body).Decode(into)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func normalizeShopifyShopDomain(value string) (string, error) {
	domain := strings.TrimSpace(strings.ToLower(value))
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")

	if domain == "" {
		return "", errors.New("missing shopify shop domain")
	}
	if strings.Contains(domain, "/") {
		return "", errors.New("invalid shopify shop domain")
	}

	return domain, nil
}

func normalizeShopifyScopes(scopes []string) []string {
	clean := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))

	for _, scope := range scopes {
		s := strings.TrimSpace(scope)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		clean = append(clean, s)
	}

	if len(clean) == 0 {
		clean = []string{"read_products"}
	}

	return []string{strings.Join(clean, ",")}
}

func canonicalShopifyCallbackQuery(rawQuery string) string {
	if strings.TrimSpace(rawQuery) == "" {
		return ""
	}

	parts := strings.Split(rawQuery, "&")
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}

		key := part
		if idx := strings.Index(part, "="); idx >= 0 {
			key = part[:idx]
		}
		if key == "hmac" || key == "signature" {
			continue
		}

		filtered = append(filtered, part)
	}

	if len(filtered) == 0 {
		return ""
	}

	sort.Strings(filtered)
	return strings.Join(filtered, "&")
}
