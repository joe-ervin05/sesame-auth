package sessions

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

type Session struct {
	ID             string
	SecretHash     []byte
	UserID         string
	AuthLevel      int
	LastVerifiedAt time.Time
	CreatedAt      time.Time
}

type User struct {
	ID            string
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
}

const sessionTokenLength = 21

const (
	SessionAuthLevelPrimary = 1
	SessionAuthLevelFull    = 2
)

func createSession(ctx context.Context, db *sql.DB, userID string, authLevel int) (token string, err error) {
	if authLevel != SessionAuthLevelPrimary && authLevel != SessionAuthLevelFull {
		authLevel = SessionAuthLevelFull
	}

	id, err := gonanoid.New(sessionTokenLength)
	if err != nil {
		return "", err
	}

	secret, err := gonanoid.New(sessionTokenLength)
	if err != nil {
		return "", err
	}

	secretHash := hashSecret(secret)
	now := time.Now().UTC()

	_, err = db.ExecContext(ctx,
		"INSERT INTO sessions (id, secret_hash, user_id, auth_level, last_verified_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, secretHash, userID, authLevel, now.Unix(), now.Unix(),
	)
	if err != nil {
		return "", err
	}

	return id + "." + secret, nil
}

func hashSecret(secret string) []byte {
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}

var ErrInvalidSession = errors.New("invalid session")

func validateSession(ctx context.Context, db *sql.DB, token string, inactivityTimeout, activityCheckInterval time.Duration) (session *Session, user *User, shouldRefresh bool, err error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, nil, false, ErrInvalidSession
	}

	sessionID, secret := parts[0], parts[1]

	if len(sessionID) != sessionTokenLength || len(secret) != sessionTokenLength {
		return nil, nil, false, ErrInvalidSession
	}

	session, user, err = getSessionAndUser(ctx, db, sessionID)
	if err != nil {
		return nil, nil, false, err
	}
	if session == nil || user == nil {
		return nil, nil, false, ErrInvalidSession
	}

	now := time.Now().UTC()
	secretHash := hashSecret(secret)
	if subtle.ConstantTimeCompare(secretHash, session.SecretHash) != 1 {
		return nil, nil, false, ErrInvalidSession
	}

	if now.Sub(session.LastVerifiedAt) >= inactivityTimeout {
		_ = deleteSession(ctx, db, sessionID)
		return nil, nil, false, ErrInvalidSession
	}

	if now.Sub(session.LastVerifiedAt) >= activityCheckInterval {
		err = updateSessionLastVerifiedAt(ctx, db, sessionID, now)
		if err != nil {
			return nil, nil, false, err
		}
		session.LastVerifiedAt = now
		shouldRefresh = true
	}

	return session, user, shouldRefresh, nil
}

func getSessionAndUser(ctx context.Context, db *sql.DB, sessionID string) (*Session, *User, error) {
	row := db.QueryRowContext(ctx,
		`SELECT
      s.id, s.secret_hash, s.user_id, s.auth_level, s.last_verified_at, s.created_at,
      u.id, u.email, u.email_verified, u.created_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.id = ?`,
		sessionID,
	)

	var session Session
	var user User
	var sessionLastVerifiedAt int64
	var sessionCreatedAt int64
	var userCreatedAt int64
	var emailVerified int
	var email sql.NullString
	err := row.Scan(
		&session.ID,
		&session.SecretHash,
		&session.UserID,
		&session.AuthLevel,
		&sessionLastVerifiedAt,
		&sessionCreatedAt,
		&user.ID,
		&email,
		&emailVerified,
		&userCreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	session.LastVerifiedAt = time.Unix(sessionLastVerifiedAt, 0).UTC()
	session.CreatedAt = time.Unix(sessionCreatedAt, 0).UTC()
	if email.Valid {
		user.Email = email.String
	}
	user.EmailVerified = emailVerified == 1
	user.CreatedAt = time.Unix(userCreatedAt, 0).UTC()

	return &session, &user, nil
}

func updateSessionLastVerifiedAt(ctx context.Context, db *sql.DB, sessionID string, now time.Time) error {
	_, err := db.ExecContext(ctx,
		"UPDATE sessions SET last_verified_at = ? WHERE id = ?",
		now.Unix(), sessionID,
	)
	return err
}

func upgradeSessionToFull(ctx context.Context, db *sql.DB, sessionID string) error {
	_, err := db.ExecContext(ctx,
		"UPDATE sessions SET auth_level = ? WHERE id = ?",
		SessionAuthLevelFull, sessionID,
	)
	return err
}

func deleteSession(ctx context.Context, db *sql.DB, sessionID string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE id = ?", sessionID)
	return err
}

func deleteUserSessions(ctx context.Context, db *sql.DB, userID string) error {
	_, err := db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	return err
}
