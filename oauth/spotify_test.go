package oauth

import "testing"

func TestSpotifyPseudoEmail(t *testing.T) {
	f := &spotifyIdentityFetcher{pseudoEmailDomain: "users.noreply.example"}
	got := f.pseudoEmail(&spotifyMe{ID: "User_123"})
	want := "user_123@users.noreply.example"
	if got != want {
		t.Fatalf("unexpected pseudo email: got %q want %q", got, want)
	}
}
