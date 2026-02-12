package oauth

import "testing"

func TestTwitterPseudoEmail(t *testing.T) {
	f := &twitterIdentityFetcher{pseudoEmailDomain: "users.noreply.example"}
	got := f.pseudoEmail(twitterUser{ID: "123", Username: "Some.User"})
	want := "some.user-123@users.noreply.example"
	if got != want {
		t.Fatalf("unexpected pseudo email: got %q want %q", got, want)
	}
}
