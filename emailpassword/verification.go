package emailpassword

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"math/big"
	"strings"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

func GenerateVerificationCode() (string, error) {
	const digits = "0123456789"
	code := make([]byte, 8)

	for i := range code {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code[i] = digits[num.Int64()]
	}

	return string(code), nil
}

func hashCode(code string) []byte {
	hash := sha256.Sum256([]byte(code))
	return hash[:]
}

const EmailVerificationExpiry = 15 * time.Minute

type EmailVerificationCode struct {
	ID        string
	UserID    string
	Email     string
	CodeHash  []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

func createEmailVerificationCode(ctx context.Context, db *sql.DB, userID, email string) (string, error) {
	_, err := db.ExecContext(ctx, "DELETE FROM email_verification_codes WHERE user_id = ?", userID)
	if err != nil {
		return "", err
	}

	code, err := GenerateVerificationCode()
	if err != nil {
		return "", err
	}

	id, err := gonanoid.New()
	if err != nil {
		return "", err
	}

	now := time.Now().UTC()
	expiresAt := now.Add(EmailVerificationExpiry)

	_, err = db.ExecContext(ctx,
		"INSERT INTO email_verification_codes (id, user_id, email, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, userID, NormalizeEmail(email), hashCode(code), expiresAt.Unix(), now.Unix(),
	)
	if err != nil {
		return "", err
	}

	return code, nil
}

var ErrInvalidCode = errors.New("invalid or expired code")
var ErrEmailAlreadyVerified = errors.New("email already verified")
var ErrUserNotFound = errors.New("user not found")
var ErrEmailMissing = errors.New("email missing")

func issueEmailVerificationCode(ctx context.Context, db *sql.DB, userID string) (*User, string, error) {
	row := db.QueryRowContext(ctx,
		"SELECT email, email_verified FROM users WHERE id = ?",
		userID,
	)

	var email sql.NullString
	var emailVerified int
	err := row.Scan(&email, &emailVerified)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrUserNotFound
	}
	if err != nil {
		return nil, "", err
	}

	if emailVerified == 1 {
		return nil, "", ErrEmailAlreadyVerified
	}

	if !email.Valid || strings.TrimSpace(email.String) == "" {
		return nil, "", ErrEmailMissing
	}

	code, err := createEmailVerificationCode(ctx, db, userID, email.String)
	if err != nil {
		return nil, "", err
	}

	return &User{ID: userID, Email: NormalizeEmail(email.String), EmailVerified: false}, code, nil
}

func verifyEmailCode(ctx context.Context, db *sql.DB, userID, code string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`DELETE FROM email_verification_codes
    WHERE user_id = ?
      AND code_hash = ?
      AND expires_at > ?
    RETURNING email`,
		userID, hashCode(code), time.Now().UTC().Unix(),
	)

	var codeEmail string
	err = row.Scan(&codeEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidCode
	}
	if err != nil {
		return err
	}

	result, err := tx.ExecContext(ctx,
		"UPDATE users SET email_verified = 1 WHERE id = ? AND email = ?",
		userID, codeEmail,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrInvalidCode
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}
