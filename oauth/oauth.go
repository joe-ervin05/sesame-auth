package oauth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/mattn/go-sqlite3"
)

func GetOrCreateUserFromOAuth(ctx context.Context, db *sql.DB, provider, providerUserID, email string, emailVerified bool) (string, error) {
	userID, err := getUserIDByOAuthAccount(ctx, db, provider, providerUserID)
	if err != nil {
		return "", err
	}
	if userID != "" {
		return userID, nil
	}

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	if normalizedEmail == "" {
		return "", ErrOAuthEmailMissing
	}

	if emailVerified && normalizedEmail != "" {
		existingUserID, err := getUserIDByEmail(ctx, db, normalizedEmail)
		if err != nil {
			return "", err
		}
		if existingUserID != "" {
			oauthAccountID, err := gonanoid.New()
			if err != nil {
				return "", err
			}

			now := time.Now().UTC().Unix()
			_, err = db.ExecContext(ctx,
				"INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, created_at) VALUES (?, ?, ?, ?, ?)",
				oauthAccountID, existingUserID, provider, providerUserID, now,
			)
			if err != nil {
				return "", err
			}

			return existingUserID, nil
		}
	}

	if !emailVerified && normalizedEmail != "" {
		existingUserID, err := getUserIDByEmail(ctx, db, normalizedEmail)
		if err != nil {
			return "", err
		}
		if existingUserID != "" {
			return "", ErrOAuthEmailAlreadyRegistered
		}
	}

	newUserID, err := gonanoid.New(12)
	if err != nil {
		return "", err
	}

	oauthAccountID, err := gonanoid.New()
	if err != nil {
		return "", err
	}

	emailVerifiedInt := 0
	if emailVerified && normalizedEmail != "" {
		emailVerifiedInt = 1
	}

	now := time.Now().UTC().Unix()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		"INSERT INTO users (id, email, email_verified, created_at) VALUES (?, ?, ?, ?)",
		newUserID, normalizedEmail, emailVerifiedInt, now,
	)
	if err != nil {
		if isSQLiteUniqueConstraint(err) {
			return "", ErrOAuthEmailAlreadyRegistered
		}
		return "", err
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, created_at) VALUES (?, ?, ?, ?, ?)",
		oauthAccountID, newUserID, provider, providerUserID, now,
	)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return newUserID, nil
}

func isSQLiteUniqueConstraint(err error) bool {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) &&
		sqliteErr.Code == sqlite3.ErrConstraint &&
		sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
		return true
	}
	return false
}

func getUserIDByOAuthAccount(ctx context.Context, db *sql.DB, provider, providerUserID string) (string, error) {
	row := db.QueryRowContext(ctx,
		"SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?",
		provider, providerUserID,
	)

	var userID string
	err := row.Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return userID, nil
}

func getUserIDByEmail(ctx context.Context, db *sql.DB, email string) (string, error) {
	row := db.QueryRowContext(ctx,
		"SELECT id FROM users WHERE email = ?",
		email,
	)

	var userID string
	err := row.Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return userID, nil
}
