package emailpassword

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/mattn/go-sqlite3"
)

type User struct {
	ID            string
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
}

var (
	ErrInvalidEmail           = errors.New("invalid email")
	ErrPasswordTooShort       = errors.New("password too short")
	ErrPasswordTooLong        = errors.New("password too long")
	ErrInvalidEmailOrPassword = errors.New("invalid email or password")
)

type PasswordTooShortError struct {
	MinLength int
}

func (e PasswordTooShortError) Error() string {
	return "password must be at least " + strconv.Itoa(e.MinLength) + " characters"
}

func (e PasswordTooShortError) Is(target error) bool {
	return target == ErrPasswordTooShort
}

func NormalizeEmail(email string) string {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)
	return email
}

func ValidateEmail(email string) error {
	if !strings.Contains(email, "@") || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
		return ErrInvalidEmail
	}
	return nil
}

func ValidatePassword(password string) error {
	return ValidatePasswordWithMinLength(password, 12)
}

func ValidatePasswordWithMinLength(password string, minLength int) error {
	if minLength <= 0 {
		minLength = 12
	}

	if utf8.RuneCountInString(password) < minLength {
		return PasswordTooShortError{MinLength: minLength}
	}
	if len(password) > 1024 {
		return ErrPasswordTooLong
	}
	return nil
}

var ErrEmailTaken = errors.New("email already registered")

type UserWithPassword struct {
	User
	PasswordHash string
}

func signup(ctx context.Context, db *sql.DB, email, password string, policy passwordPolicy) (*User, error) {
	email = NormalizeEmail(email)

	if err := ValidateEmail(email); err != nil {
		return nil, err
	}
	if err := ValidatePasswordWithMinLength(password, policy.minPasswordLength); err != nil {
		return nil, err
	}
	if policy.breachChecker != nil {
		if err := policy.breachChecker(ctx, password); err != nil {
			return nil, err
		}
	}

	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	id, err := gonanoid.New(12)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	_, err = db.ExecContext(ctx,
		"INSERT INTO users (id, email, email_verified, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
		id, email, 0, passwordHash, now.Unix(),
	)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) &&
			sqliteErr.Code == sqlite3.ErrConstraint &&
			sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			return nil, ErrEmailTaken
		}
		return nil, err
	}

	return &User{
		ID:            id,
		Email:         email,
		EmailVerified: false,
		CreatedAt:     now,
	}, nil
}

func login(ctx context.Context, db *sql.DB, email, password string) (*User, error) {

	// argon2id hash for "dummy-password" with minimum recommended config
	dummyHash := "$argon2id$v=19$m=19456,t=2,p=1$rWIBINRiU62BKAlviyjjmQ$MGCsB33h8NmJMeO5rAVhUJg6tszbm2aoALebdBTzytQ"

	userWithPassword, err := GetUserPasswordByEmail(ctx, db, email)
	if err != nil {
		return nil, err
	}

	hashToCompare := dummyHash
	if userWithPassword != nil && userWithPassword.PasswordHash != "" {
		hashToCompare = userWithPassword.PasswordHash
	}

	valid := VerifyPassword(password, hashToCompare)

	if userWithPassword == nil || !valid {
		return nil, ErrInvalidEmailOrPassword
	}

	return &userWithPassword.User, nil

}

func GetUserPasswordByEmail(ctx context.Context, db *sql.DB, email string) (*UserWithPassword, error) {
	email = NormalizeEmail(email)

	row := db.QueryRowContext(ctx,
		"SELECT id, email, email_verified, password_hash, created_at FROM users WHERE email = ?",
		email,
	)

	var user UserWithPassword
	var createdAt int64
	var emailVerified int
	var passHash sql.NullString
	err := row.Scan(&user.ID, &user.Email, &emailVerified, &passHash, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if passHash.Valid {
		user.PasswordHash = passHash.String
	}

	user.EmailVerified = emailVerified == 1
	user.CreatedAt = time.Unix(createdAt, 0).UTC()

	return &user, nil
}
