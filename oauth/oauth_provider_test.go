package oauth

import "testing"

func TestOAuthProvidersFromEnvNoProvidersConfigured(t *testing.T) {
	t.Setenv("OAUTH_SPOTIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SPOTIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SPOTIFY_PSEUDO_EMAIL_DOMAIN", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_ID", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_SECRET", "")
	t.Setenv("OAUTH_TWITTER_PSEUDO_EMAIL_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "")
	t.Setenv("OAUTH_REDDIT_PSEUDO_EMAIL_DOMAIN", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("APP_BASE_URL", "http://localhost:8080")

	_, err := OAuthProvidersFromEnv()
	if err == nil {
		t.Fatal("expected error when no oauth providers are configured")
	}
	if got := err.Error(); got != "no oauth providers configured" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOAuthProvidersFromEnvSpotifyConfigured(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_ID", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SPOTIFY_CLIENT_ID", "spotify-client-id")
	t.Setenv("OAUTH_SPOTIFY_CLIENT_SECRET", "spotify-client-secret")
	t.Setenv("OAUTH_SPOTIFY_DISPLAY_NAME", "Spotify")

	providers, err := OAuthProvidersFromEnv()
	if err != nil {
		t.Fatalf("expected spotify provider config to work, got error: %v", err)
	}

	provider, ok := providers["spotify"]
	if !ok {
		t.Fatalf("expected spotify provider in map, got keys: %#v", providers)
	}

	if got := provider.Name(); got != "spotify" {
		t.Fatalf("expected provider name spotify, got %q", got)
	}
}

func TestOAuthProvidersFromEnvSpotifyRedirectOverride(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_ID", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SPOTIFY_CLIENT_ID", "spotify-client-id")
	t.Setenv("OAUTH_SPOTIFY_CLIENT_SECRET", "spotify-client-secret")
	t.Setenv("OAUTH_SPOTIFY_REDIRECT_URL", "http://127.0.0.1:8080/oauth/spotify/callback")

	providers, err := OAuthProvidersFromEnv()
	if err != nil {
		t.Fatalf("expected spotify provider config to work, got error: %v", err)
	}

	rawProvider, ok := providers["spotify"]
	if !ok {
		t.Fatalf("expected spotify provider in map, got keys: %#v", providers)
	}

	provider, ok := rawProvider.(*SpotifyProvider)
	if !ok {
		t.Fatalf("expected spotify provider type, got %T", rawProvider)
	}

	if got := provider.oauth2Cfg.RedirectURL; got != "http://127.0.0.1:8080/oauth/spotify/callback" {
		t.Fatalf("unexpected spotify redirect url: %q", got)
	}
}

func TestOAuthProvidersFromEnvSpotifyMissingSecret(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_ID", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SPOTIFY_CLIENT_ID", "spotify-client-id")
	t.Setenv("OAUTH_SPOTIFY_CLIENT_SECRET", "")

	_, err := OAuthProvidersFromEnv()
	if err == nil {
		t.Fatal("expected missing spotify secret to fail")
	}

	if got := err.Error(); got != "missing OAUTH_SPOTIFY_CLIENT_SECRET" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOAuthProvidersFromEnvTwitterConfigured(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_ID", "twitter-client-id")
	t.Setenv("OAUTH_TWITTER_CLIENT_SECRET", "twitter-client-secret")
	t.Setenv("OAUTH_TWITTER_DISPLAY_NAME", "Twitter")

	providers, err := OAuthProvidersFromEnv()
	if err != nil {
		t.Fatalf("expected twitter provider config to work, got error: %v", err)
	}

	provider, ok := providers["twitter"]
	if !ok {
		t.Fatalf("expected twitter provider in map, got keys: %#v", providers)
	}

	if got := provider.Name(); got != "twitter" {
		t.Fatalf("expected provider name twitter, got %q", got)
	}
}

func TestOAuthProvidersFromEnvTwitterMissingSecret(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "")
	t.Setenv("OAUTH_TWITTER_CLIENT_ID", "twitter-client-id")
	t.Setenv("OAUTH_TWITTER_CLIENT_SECRET", "")

	_, err := OAuthProvidersFromEnv()
	if err == nil {
		t.Fatal("expected missing twitter secret to fail")
	}

	if got := err.Error(); got != "missing OAUTH_TWITTER_CLIENT_SECRET" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOAuthProvidersFromEnvRedditConfigured(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "reddit-client-id")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "reddit-client-secret")
	t.Setenv("OAUTH_REDDIT_DISPLAY_NAME", "Reddit")

	providers, err := OAuthProvidersFromEnv()
	if err != nil {
		t.Fatalf("expected reddit provider config to work, got error: %v", err)
	}

	provider, ok := providers["reddit"]
	if !ok {
		t.Fatalf("expected reddit provider in map, got keys: %#v", providers)
	}

	if got := provider.Name(); got != "reddit" {
		t.Fatalf("expected provider name reddit, got %q", got)
	}
}

func TestOAuthProvidersFromEnvRedditMissingSecret(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")
	t.Setenv("OAUTH_REDDIT_CLIENT_ID", "reddit-client-id")
	t.Setenv("OAUTH_REDDIT_CLIENT_SECRET", "")

	_, err := OAuthProvidersFromEnv()
	if err == nil {
		t.Fatal("expected missing reddit secret to fail")
	}

	if got := err.Error(); got != "missing OAUTH_REDDIT_CLIENT_SECRET" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOAuthProvidersFromEnvShopifyConfigured(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "shopify-client-id")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "shopify-client-secret")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "example-store.myshopify.com")

	providers, err := OAuthProvidersFromEnv()
	if err != nil {
		t.Fatalf("expected shopify provider config to work, got error: %v", err)
	}

	provider, ok := providers["shopify"]
	if !ok {
		t.Fatalf("expected shopify provider in map, got keys: %#v", providers)
	}

	if got := provider.Name(); got != "shopify" {
		t.Fatalf("expected provider name shopify, got %q", got)
	}
}

func TestOAuthProvidersFromEnvShopifyMissingShopDomain(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_ID", "shopify-client-id")
	t.Setenv("OAUTH_SHOPIFY_CLIENT_SECRET", "shopify-client-secret")
	t.Setenv("OAUTH_SHOPIFY_SHOP_DOMAIN", "")

	_, err := OAuthProvidersFromEnv()
	if err == nil {
		t.Fatal("expected missing shopify shop domain to fail")
	}

	if got := err.Error(); got != "missing OAUTH_SHOPIFY_SHOP_DOMAIN" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOAuthProvidersFromEnvDiscordConfigured(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "discord-client-id")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "discord-client-secret")
	t.Setenv("OAUTH_DISCORD_DISPLAY_NAME", "Discord")

	providers, err := OAuthProvidersFromEnv()
	if err != nil {
		t.Fatalf("expected discord provider config to work, got error: %v", err)
	}

	provider, ok := providers["discord"]
	if !ok {
		t.Fatalf("expected discord provider in map, got keys: %#v", providers)
	}

	if got := provider.Name(); got != "discord" {
		t.Fatalf("expected provider name discord, got %q", got)
	}
}

func TestOAuthProvidersFromEnvDiscordMissingSecret(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")
	t.Setenv("OAUTH_DISCORD_CLIENT_ID", "discord-client-id")
	t.Setenv("OAUTH_DISCORD_CLIENT_SECRET", "")

	_, err := OAuthProvidersFromEnv()
	if err == nil {
		t.Fatal("expected missing discord secret to fail")
	}

	if got := err.Error(); got != "missing OAUTH_DISCORD_CLIENT_SECRET" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOAuthProvidersFromEnvGitHubConfigured(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "gh-client-id")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "gh-client-secret")
	t.Setenv("OAUTH_GITHUB_DISPLAY_NAME", "GitHub")

	providers, err := OAuthProvidersFromEnv()
	if err != nil {
		t.Fatalf("expected github provider config to work, got error: %v", err)
	}

	provider, ok := providers["github"]
	if !ok {
		t.Fatalf("expected github provider in map, got keys: %#v", providers)
	}

	if got := provider.Name(); got != "github" {
		t.Fatalf("expected provider name github, got %q", got)
	}
}

func TestOAuthProvidersFromEnvGitHubMissingSecret(t *testing.T) {
	t.Setenv("APP_BASE_URL", "http://localhost:8080")
	t.Setenv("OAUTH_OIDC_PROVIDERS", "")
	t.Setenv("OAUTH_GITHUB_CLIENT_ID", "gh-client-id")
	t.Setenv("OAUTH_GITHUB_CLIENT_SECRET", "")

	_, err := OAuthProvidersFromEnv()
	if err == nil {
		t.Fatal("expected missing github secret to fail")
	}

	if got := err.Error(); got != "missing OAUTH_GITHUB_CLIENT_SECRET" {
		t.Fatalf("unexpected error: %v", err)
	}
}
