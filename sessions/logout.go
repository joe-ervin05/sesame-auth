package sessions

import (
	"context"
	"database/sql"
	"net/http"
)

func logout(ctx context.Context, db *sql.DB) (string, error) {
	session := GetSession(ctx)
	if session == nil {
		return "", nil
	}

	err := deleteSession(ctx, db, session.ID)
	if err != nil {
		return "", err
	}

	return session.ID, nil
}

// LogoutHTTP is idempotent: it clears the session cookie even when
// there is no current authenticated session in context.
func logoutHTTP(w http.ResponseWriter, r *http.Request, db *sql.DB, opts cookieOptions) error {
	session := GetSession(r.Context())
	if session != nil {
		err := deleteSession(r.Context(), db, session.ID)
		if err != nil {
			return err
		}
	}

	clearSessionCookie(w, opts)
	return nil
}
