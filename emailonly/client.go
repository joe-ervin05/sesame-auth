package emailonly

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/atomicbase/sesame/mailer"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

var (
	ErrInvalidEmail              = errors.New("invalid email")
	ErrInvalidOrExpiredMagicLink = errors.New("invalid or expired magic link")
	ErrInvalidOrExpiredOTP       = errors.New("invalid or expired otp")
)

type ClientConfig struct {
	DB           *sql.DB
	Mailer       mailer.Mailer
	AppName      string
	AppBaseURL   string
	Emails       EmailsConfig
	MagicLinkTTL time.Duration
	OTPTTL       time.Duration
	OTPDigits    int
}

type Client struct {
	db           *sql.DB
	mailer       mailer.Mailer
	appName      string
	appBaseURL   string
	emails       EmailsConfig
	magicLinkTTL time.Duration
	otpTTL       time.Duration
	otpDigits    int
}

type MagicLinkTemplateData struct {
	AppName     string
	Email       string
	MagicLink   string
	ExpiresIn   time.Duration
	RequestedAt time.Time
}

type OTPTemplateData struct {
	AppName     string
	Email       string
	Code        string
	ExpiresIn   time.Duration
	RequestedAt time.Time
}

type MagicLinkTemplate func(data MagicLinkTemplateData) (mailer.Content, error)
type OTPTemplate func(data OTPTemplateData) (mailer.Content, error)

type EmailsConfig struct {
	MagicLink MagicLinkTemplate
	OTP       OTPTemplate
}

type User struct {
	ID            string
	Email         string
	EmailVerified bool
	CreatedAt     time.Time
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.DB == nil {
		return nil, errors.New("emailonly client requires db")
	}
	if cfg.Mailer == nil {
		cfg.Mailer = mailer.LogMailer{}
	}
	if strings.TrimSpace(cfg.AppName) == "" {
		cfg.AppName = "Sesame"
	}
	if strings.TrimSpace(cfg.AppBaseURL) == "" {
		cfg.AppBaseURL = "http://localhost:8080"
	}
	if cfg.Emails.MagicLink == nil {
		cfg.Emails.MagicLink = DefaultMagicLinkTemplate
	}
	if cfg.Emails.OTP == nil {
		cfg.Emails.OTP = DefaultOTPTemplate
	}

	magicLinkTTL := cfg.MagicLinkTTL
	if magicLinkTTL <= 0 {
		magicLinkTTL = 15 * time.Minute
	}

	otpTTL := cfg.OTPTTL
	if otpTTL <= 0 {
		otpTTL = 10 * time.Minute
	}

	otpDigits := cfg.OTPDigits
	if otpDigits <= 0 {
		otpDigits = 6
	}
	if otpDigits < 4 || otpDigits > 10 {
		return nil, errors.New("otp digits must be between 4 and 10")
	}

	return &Client{
		db:           cfg.DB,
		mailer:       cfg.Mailer,
		appName:      cfg.AppName,
		appBaseURL:   strings.TrimRight(cfg.AppBaseURL, "/"),
		emails:       cfg.Emails,
		magicLinkTTL: magicLinkTTL,
		otpTTL:       otpTTL,
		otpDigits:    otpDigits,
	}, nil
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateEmail(email string) error {
	if !strings.Contains(email, "@") || strings.HasPrefix(email, "@") || strings.HasSuffix(email, "@") {
		return ErrInvalidEmail
	}
	return nil
}

func (c *Client) BeginMagicLink(ctx context.Context, email string) (string, error) {
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return "", err
	}

	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	tokenHash := sha256.Sum256([]byte(token))
	id, err := gonanoid.New()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	_, err = c.db.ExecContext(ctx,
		`INSERT INTO email_magic_links (id, email, token_hash, created_at, expires_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(email) DO UPDATE SET
  id = excluded.id,
  token_hash = excluded.token_hash,
  created_at = excluded.created_at,
  expires_at = excluded.expires_at`,
		id, email, tokenHash[:], now.Unix(), now.Add(c.magicLinkTTL).Unix(),
	)
	if err != nil {
		return "", err
	}

	content, err := c.emails.MagicLink(MagicLinkTemplateData{
		AppName:     c.appName,
		Email:       email,
		MagicLink:   buildMagicLinkURL(c.appBaseURL, token),
		ExpiresIn:   c.magicLinkTTL,
		RequestedAt: now,
	})
	if err != nil {
		return "", err
	}

	err = c.mailer.Send(ctx, mailer.Message{
		To:       email,
		Subject:  content.Subject,
		TextBody: content.TextBody,
		HTMLBody: content.HTMLBody,
	})
	if err != nil {
		return "", err
	}

	return token, nil
}

func (c *Client) CompleteMagicLink(ctx context.Context, token string) (*User, bool, error) {
	tokenHash := sha256.Sum256([]byte(strings.TrimSpace(token)))
	now := time.Now().UTC().Unix()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`DELETE FROM email_magic_links
WHERE token_hash = ? AND expires_at > ?
RETURNING email`,
		tokenHash[:], now,
	)

	var email string
	err = row.Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrInvalidOrExpiredMagicLink
	}
	if err != nil {
		return nil, false, err
	}

	user, created, err := getOrCreateVerifiedUserByEmailTx(ctx, tx, email)
	if err != nil {
		return nil, false, err
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}

	return user, created, nil
}

func (c *Client) BeginOTP(ctx context.Context, email string) (string, error) {
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return "", err
	}

	code, err := generateDigits(c.otpDigits)
	if err != nil {
		return "", err
	}
	codeHash := sha256.Sum256([]byte(code))
	id, err := gonanoid.New()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	_, err = c.db.ExecContext(ctx,
		`INSERT INTO email_otp_codes (id, email, code_hash, created_at, expires_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(email) DO UPDATE SET
  id = excluded.id,
  code_hash = excluded.code_hash,
  created_at = excluded.created_at,
  expires_at = excluded.expires_at`,
		id, email, codeHash[:], now.Unix(), now.Add(c.otpTTL).Unix(),
	)
	if err != nil {
		return "", err
	}

	content, err := c.emails.OTP(OTPTemplateData{
		AppName:     c.appName,
		Email:       email,
		Code:        code,
		ExpiresIn:   c.otpTTL,
		RequestedAt: now,
	})
	if err != nil {
		return "", err
	}

	err = c.mailer.Send(ctx, mailer.Message{
		To:       email,
		Subject:  content.Subject,
		TextBody: content.TextBody,
		HTMLBody: content.HTMLBody,
	})
	if err != nil {
		return "", err
	}

	return code, nil
}

func (c *Client) CompleteOTP(ctx context.Context, email, code string) (*User, bool, error) {
	email = NormalizeEmail(email)
	if err := ValidateEmail(email); err != nil {
		return nil, false, err
	}

	code = strings.TrimSpace(code)
	if code == "" {
		return nil, false, ErrInvalidOrExpiredOTP
	}

	codeHash := sha256.Sum256([]byte(code))
	now := time.Now().UTC().Unix()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx,
		`DELETE FROM email_otp_codes
WHERE email = ? AND code_hash = ? AND expires_at > ?
RETURNING email`,
		email, codeHash[:], now,
	)

	var matchedEmail string
	err = row.Scan(&matchedEmail)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, ErrInvalidOrExpiredOTP
	}
	if err != nil {
		return nil, false, err
	}

	user, created, err := getOrCreateVerifiedUserByEmailTx(ctx, tx, matchedEmail)
	if err != nil {
		return nil, false, err
	}

	if err := tx.Commit(); err != nil {
		return nil, false, err
	}

	return user, created, nil
}

func getOrCreateVerifiedUserByEmailTx(ctx context.Context, tx *sql.Tx, email string) (*User, bool, error) {
	now := time.Now().UTC()

	id, err := gonanoid.New(12)
	if err != nil {
		return nil, false, err
	}

	_, err = tx.ExecContext(ctx,
		"INSERT INTO users (id, email, email_verified, created_at) VALUES (?, ?, 1, ?) ON CONFLICT(email) DO NOTHING",
		id, email, now.Unix(),
	)
	if err != nil {
		return nil, false, err
	}

	row := tx.QueryRowContext(ctx,
		"SELECT id, email, email_verified, created_at FROM users WHERE email = ?",
		email,
	)

	var user User
	var verified int
	var createdAt int64
	if err := row.Scan(&user.ID, &user.Email, &verified, &createdAt); err != nil {
		return nil, false, err
	}

	created := user.ID == id

	if verified == 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE users SET email_verified = 1 WHERE id = ?", user.ID); err != nil {
			return nil, false, err
		}
		verified = 1
	}

	user.EmailVerified = verified == 1
	user.CreatedAt = time.Unix(createdAt, 0).UTC()

	return &user, created, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateDigits(length int) (string, error) {
	const digits = "0123456789"
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b[i] = digits[n.Int64()]
	}
	return string(b), nil
}

func DefaultMagicLinkTemplate(data MagicLinkTemplateData) (mailer.Content, error) {
	appName := strings.TrimSpace(data.AppName)
	if appName == "" {
		appName = "Sesame"
	}

	return mailer.Content{
		Subject: fmt.Sprintf("%s sign in link", appName),
		TextBody: fmt.Sprintf(
			"Use this magic link to sign in: %s\n\nThis link expires in %s.",
			data.MagicLink,
			data.ExpiresIn.Round(time.Minute).String(),
		),
		HTMLBody: fmt.Sprintf(
			"<p>Use this magic link to sign in:</p><p><a href=\"%s\">Sign in</a></p><p>This link expires in %s.</p>",
			data.MagicLink,
			data.ExpiresIn.Round(time.Minute).String(),
		),
	}, nil
}

func DefaultOTPTemplate(data OTPTemplateData) (mailer.Content, error) {
	appName := strings.TrimSpace(data.AppName)
	if appName == "" {
		appName = "Sesame"
	}

	return mailer.Content{
		Subject: fmt.Sprintf("%s one-time code", appName),
		TextBody: fmt.Sprintf(
			"Your one-time code is: %s\n\nThis code expires in %s.",
			data.Code,
			data.ExpiresIn.Round(time.Minute).String(),
		),
		HTMLBody: fmt.Sprintf(
			"<p>Your one-time code is:</p><p><strong>%s</strong></p><p>This code expires in %s.</p>",
			data.Code,
			data.ExpiresIn.Round(time.Minute).String(),
		),
	}, nil
}

func buildMagicLinkURL(appBaseURL, token string) string {
	base := strings.TrimRight(strings.TrimSpace(appBaseURL), "/")
	if base == "" {
		base = "http://localhost:8080"
	}
	return fmt.Sprintf("%s/email/magic-link/complete?token=%s", base, url.QueryEscape(token))
}
