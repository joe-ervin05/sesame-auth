package oauth

import "testing"

func TestRedditPseudoEmail(t *testing.T) {
	f := &redditIdentityFetcher{pseudoEmailDomain: "users.noreply.example"}
	got := f.pseudoEmail(&redditMe{ID: "t2_AbC123", Name: "Some.User-Name"})
	want := "some.user-name-t2_abc123@users.noreply.example"
	if got != want {
		t.Fatalf("unexpected pseudo email: got %q want %q", got, want)
	}
}

func TestSanitizeLocalPart(t *testing.T) {
	got := sanitizeLocalPart(" __A B+C__ ")
	want := "abc"
	if got != want {
		t.Fatalf("unexpected sanitized local part: got %q want %q", got, want)
	}
}
