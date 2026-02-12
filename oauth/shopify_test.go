package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"testing"
)

func TestCanonicalShopifyCallbackQuery(t *testing.T) {
	raw := "state=abc&hmac=deadbeef&shop=test-shop.myshopify.com&code=123&timestamp=12345&signature=legacy"
	got := canonicalShopifyCallbackQuery(raw)
	want := "code=123&shop=test-shop.myshopify.com&state=abc&timestamp=12345"
	if got != want {
		t.Fatalf("unexpected canonical payload: got %q want %q", got, want)
	}
}

func TestShopifyValidateCallback(t *testing.T) {
	p, err := NewShopifyProvider(ShopifyProviderConfig{
		ClientID:     "client-id",
		ClientSecret: "secret-key",
		RedirectURL:  "http://localhost:8080/oauth/shopify/callback",
		ShopDomain:   "test-shop.myshopify.com",
		Scopes:       []string{"read_products"},
	})
	if err != nil {
		t.Fatalf("new shopify provider: %v", err)
	}

	rawWithoutHMAC := "code=abc123&shop=test-shop.myshopify.com&state=some-state&timestamp=1700000000"
	m := hmac.New(sha256.New, []byte("secret-key"))
	_, _ = m.Write([]byte(rawWithoutHMAC))
	h := hex.EncodeToString(m.Sum(nil))

	req := httptest.NewRequest("GET", "/oauth/shopify/callback?"+rawWithoutHMAC+"&hmac="+h, nil)
	if err := p.ValidateCallback(req); err != nil {
		t.Fatalf("expected callback validation to pass, got error: %v", err)
	}
}
