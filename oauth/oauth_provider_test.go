package oauth

import (
	"database/sql"
	"testing"
)

const testRedirectURL = "http://localhost:8080/oauth/callback"

func TestNewClientRequiresAtLeastOneProvider(t *testing.T) {
	_, err := NewClient(ClientConfig{
		DB:          &sql.DB{},
		StateSecret: "test-secret",
		Providers:   map[string]OAuthProvider{},
	})
	if err == nil {
		t.Fatal("expected error when no oauth providers are configured")
	}
	if got := err.Error(); got != "oauth client requires at least one provider" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewSpotifyProviderConfigured(t *testing.T) {
	p, err := NewSpotifyProvider(SpotifyProviderConfig{
		ClientID:     "spotify-client-id",
		ClientSecret: "spotify-client-secret",
		RedirectURL:  testRedirectURL,
		DisplayName:  "Spotify",
	})
	if err != nil {
		t.Fatalf("expected spotify provider config to work, got error: %v", err)
	}
	if got := p.Name(); got != "spotify" {
		t.Fatalf("expected provider name spotify, got %q", got)
	}
}

func TestNewSpotifyProviderRedirectOverride(t *testing.T) {
	p, err := NewSpotifyProvider(SpotifyProviderConfig{
		ClientID:     "spotify-client-id",
		ClientSecret: "spotify-client-secret",
		RedirectURL:  "http://127.0.0.1:8080/oauth/spotify/callback",
	})
	if err != nil {
		t.Fatalf("expected spotify provider config to work, got error: %v", err)
	}
	if got := p.oauth2Cfg.RedirectURL; got != "http://127.0.0.1:8080/oauth/spotify/callback" {
		t.Fatalf("unexpected spotify redirect url: %q", got)
	}
}

func TestNewSpotifyProviderMissingSecret(t *testing.T) {
	_, err := NewSpotifyProvider(SpotifyProviderConfig{
		ClientID:    "spotify-client-id",
		RedirectURL: testRedirectURL,
	})
	if err == nil {
		t.Fatal("expected missing spotify secret to fail")
	}
	if got := err.Error(); got != "missing spotify client secret" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewTwitterProviderConfigured(t *testing.T) {
	p, err := NewTwitterProvider(TwitterProviderConfig{
		ClientID:     "twitter-client-id",
		ClientSecret: "twitter-client-secret",
		RedirectURL:  testRedirectURL,
		DisplayName:  "Twitter",
	})
	if err != nil {
		t.Fatalf("expected twitter provider config to work, got error: %v", err)
	}
	if got := p.Name(); got != "twitter" {
		t.Fatalf("expected provider name twitter, got %q", got)
	}
}

func TestNewTwitterProviderMissingSecret(t *testing.T) {
	_, err := NewTwitterProvider(TwitterProviderConfig{
		ClientID:    "twitter-client-id",
		RedirectURL: testRedirectURL,
	})
	if err == nil {
		t.Fatal("expected missing twitter secret to fail")
	}
	if got := err.Error(); got != "missing twitter client secret" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewRedditProviderConfigured(t *testing.T) {
	p, err := NewRedditProvider(RedditProviderConfig{
		ClientID:     "reddit-client-id",
		ClientSecret: "reddit-client-secret",
		RedirectURL:  testRedirectURL,
		DisplayName:  "Reddit",
	})
	if err != nil {
		t.Fatalf("expected reddit provider config to work, got error: %v", err)
	}
	if got := p.Name(); got != "reddit" {
		t.Fatalf("expected provider name reddit, got %q", got)
	}
}

func TestNewRedditProviderMissingSecret(t *testing.T) {
	_, err := NewRedditProvider(RedditProviderConfig{
		ClientID:    "reddit-client-id",
		RedirectURL: testRedirectURL,
	})
	if err == nil {
		t.Fatal("expected missing reddit secret to fail")
	}
	if got := err.Error(); got != "missing reddit client secret" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewShopifyProviderConfigured(t *testing.T) {
	p, err := NewShopifyProvider(ShopifyProviderConfig{
		ClientID:     "shopify-client-id",
		ClientSecret: "shopify-client-secret",
		RedirectURL:  testRedirectURL,
		ShopDomain:   "example-store.myshopify.com",
	})
	if err != nil {
		t.Fatalf("expected shopify provider config to work, got error: %v", err)
	}
	if got := p.Name(); got != "shopify" {
		t.Fatalf("expected provider name shopify, got %q", got)
	}
}

func TestNewShopifyProviderMissingShopDomain(t *testing.T) {
	_, err := NewShopifyProvider(ShopifyProviderConfig{
		ClientID:     "shopify-client-id",
		ClientSecret: "shopify-client-secret",
		RedirectURL:  testRedirectURL,
	})
	if err == nil {
		t.Fatal("expected missing shopify shop domain to fail")
	}
	if got := err.Error(); got != "missing shopify shop domain" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDiscordProviderConfigured(t *testing.T) {
	p, err := NewDiscordProvider(DiscordProviderConfig{
		ClientID:     "discord-client-id",
		ClientSecret: "discord-client-secret",
		RedirectURL:  testRedirectURL,
		DisplayName:  "Discord",
	})
	if err != nil {
		t.Fatalf("expected discord provider config to work, got error: %v", err)
	}
	if got := p.Name(); got != "discord" {
		t.Fatalf("expected provider name discord, got %q", got)
	}
}

func TestNewDiscordProviderMissingSecret(t *testing.T) {
	_, err := NewDiscordProvider(DiscordProviderConfig{
		ClientID:    "discord-client-id",
		RedirectURL: testRedirectURL,
	})
	if err == nil {
		t.Fatal("expected missing discord secret to fail")
	}
	if got := err.Error(); got != "missing discord client secret" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewGitHubProviderConfigured(t *testing.T) {
	p, err := NewGitHubProvider(GitHubProviderConfig{
		ClientID:     "gh-client-id",
		ClientSecret: "gh-client-secret",
		RedirectURL:  testRedirectURL,
		DisplayName:  "GitHub",
	})
	if err != nil {
		t.Fatalf("expected github provider config to work, got error: %v", err)
	}
	if got := p.Name(); got != "github" {
		t.Fatalf("expected provider name github, got %q", got)
	}
}

func TestNewGitHubProviderMissingSecret(t *testing.T) {
	_, err := NewGitHubProvider(GitHubProviderConfig{
		ClientID:    "gh-client-id",
		RedirectURL: testRedirectURL,
	})
	if err == nil {
		t.Fatal("expected missing github secret to fail")
	}
	if got := err.Error(); got != "missing github client secret" {
		t.Fatalf("unexpected error: %v", err)
	}
}
