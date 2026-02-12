package emailpassword

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

const PasswordResetExpiry = 1 * time.Hour

type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

func createPasswordResetToken(ctx context.Context, db *sql.DB, userID string) (string, error) {
	_, err := db.ExecContext(ctx, "DELETE FROM password_reset_tokens WHERE user_id = ?", userID)
	if err != nil {
		return "", err
	}

	token, err := gonanoid.New(32)
	if err != nil {
		return "", err
	}

	id, err := gonanoid.New()
	if err != nil {
		return "", err
	}

	tokenHash := sha256.Sum256([]byte(token))
	now := time.Now().UTC()
	expiresAt := now.Add(PasswordResetExpiry)

	_, err = db.ExecContext(ctx,
		"INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
		id, userID, tokenHash[:], expiresAt.Unix(), now.Unix(),
	)
	if err != nil {
		return "", err
	}

	return token, nil
}

var ErrInvalidToken = errors.New("invalid or expired token")
var ErrPasswordsDoNotMatch = errors.New("passwords do not match")

func startPasswordReset(ctx context.Context, db *sql.DB, email string) (*UserWithPassword, string, error) {
	userWithPassword, err := GetUserPasswordByEmail(ctx, db, email)
	if err != nil {
		return nil, "", err
	}

	if userWithPassword == nil {
		return nil, "", nil
	}

	token, err := createPasswordResetToken(ctx, db, userWithPassword.ID)
	if err != nil {
		return nil, "", err
	}

	return userWithPassword, token, nil
}

func resetPassword(ctx context.Context, db *sql.DB, token, newPassword, confirmPassword string, policy passwordPolicy) error {
	if newPassword != confirmPassword {
		return ErrPasswordsDoNotMatch
	}

	if err := ValidatePasswordWithMinLength(newPassword, policy.minPasswordLength); err != nil {
		return err
	}

	if policy.breachChecker != nil {
		if err := policy.breachChecker(ctx, newPassword); err != nil {
			return err
		}
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tokenHash := sha256.Sum256([]byte(token))
	row := tx.QueryRowContext(ctx,
		`DELETE FROM password_reset_tokens
    WHERE token_hash = ?
      AND expires_at > ?
    RETURNING user_id`,
		tokenHash[:], time.Now().UTC().Unix(),
	)

	var userID string
	err = row.Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInvalidToken
	}
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		"UPDATE users SET password_hash = ? WHERE id = ?",
		newHash, userID,
	)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

var ErrInvalidCurrentPassword = errors.New("current password is incorrect")

func changePasswordWithConfirmation(ctx context.Context, db *sql.DB, userID, currentPassword, newPassword, confirmPassword string, policy passwordPolicy) error {
	if newPassword != confirmPassword {
		return ErrPasswordsDoNotMatch
	}

	return changePassword(ctx, db, userID, currentPassword, newPassword, policy)
}

func changePassword(ctx context.Context, db *sql.DB, userID, currentPassword, newPassword string, policy passwordPolicy) error {
	row := db.QueryRowContext(ctx,
		"SELECT password_hash FROM users WHERE id = ?",
		userID,
	)

	var currentHash string
	if err := row.Scan(&currentHash); err != nil {
		return err
	}

	if !VerifyPassword(currentPassword, currentHash) {
		return ErrInvalidCurrentPassword
	}

	if err := ValidatePasswordWithMinLength(newPassword, policy.minPasswordLength); err != nil {
		return err
	}

	if policy.breachChecker != nil {
		if err := policy.breachChecker(ctx, newPassword); err != nil {
			return err
		}
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx,
		"UPDATE users SET password_hash = ? WHERE id = ?",
		newHash, userID,
	)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}
