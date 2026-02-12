package mfa

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var ErrInvalidTwoFactorCode = errors.New("invalid two-factor code")

type ClientConfig struct {
	DB                *sql.DB
	EncryptionKey     []byte
	Issuer            string
	PendingSetupTTL   time.Duration
	RecoveryCodeCount int
}

type Client struct {
	db                *sql.DB
	encryptionKey     []byte
	issuer            string
	pendingSetupTTL   time.Duration
	recoveryCodeCount int
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.DB == nil {
		return nil, errors.New("mfa client requires db")
	}
	if len(cfg.EncryptionKey) != 32 {
		return nil, errors.New("mfa encryption key must be 32 bytes")
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		issuer = "Sesame"
	}
	setupTTL := cfg.PendingSetupTTL
	if setupTTL <= 0 {
		setupTTL = 10 * time.Minute
	}
	recoveryCount := cfg.RecoveryCodeCount
	if recoveryCount <= 0 {
		recoveryCount = 8
	}

	return &Client{
		db:                cfg.DB,
		encryptionKey:     append([]byte(nil), cfg.EncryptionKey...),
		issuer:            issuer,
		pendingSetupTTL:   setupTTL,
		recoveryCodeCount: recoveryCount,
	}, nil
}

func (c *Client) HasTwoFactorEnabled(ctx context.Context, userID string) (bool, error) {
	row := c.db.QueryRowContext(ctx, "SELECT 1 FROM user_totp_credentials WHERE user_id = ?", userID)
	var one int
	err := row.Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) GenerateTOTPSetup(accountLabel string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      c.issuer,
		AccountName: accountLabel,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

func (c *Client) VerifyTOTPCode(secret, code string, now time.Time) bool {
	valid, err := totp.ValidateCustom(code, secret, now,
		totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return false
	}
	return valid
}

func (c *Client) StartPendingSetup(ctx context.Context, userID, secret string) (string, error) {
	secretEncrypted, err := c.encryptValue(secret)
	if err != nil {
		return "", err
	}
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	tokenHash := sha256.Sum256([]byte(token))
	setupID, err := gonanoid.New()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	if _, err := c.db.ExecContext(ctx, "DELETE FROM user_totp_pending_setups WHERE user_id = ?", userID); err != nil {
		return "", err
	}

	_, err = c.db.ExecContext(ctx,
		"INSERT INTO user_totp_pending_setups (id, user_id, token_hash, secret_encrypted, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		setupID, userID, tokenHash[:], secretEncrypted, now.Unix(), now.Add(c.pendingSetupTTL).Unix(),
	)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (c *Client) LoadPendingSetupSecret(ctx context.Context, userID, token string) (string, error) {
	_, secretEncrypted, err := c.loadPendingSetup(ctx, userID, token)
	if err != nil {
		return "", err
	}
	return c.decryptValue(secretEncrypted)
}

func (c *Client) ConsumePendingSetup(ctx context.Context, userID, token string) (string, error) {
	setupID, secretEncrypted, err := c.loadPendingSetup(ctx, userID, token)
	if err != nil {
		return "", err
	}
	if _, err := c.db.ExecContext(ctx, "DELETE FROM user_totp_pending_setups WHERE id = ?", setupID); err != nil {
		return "", err
	}
	return c.decryptValue(secretEncrypted)
}

func (c *Client) UpsertUserTOTPSecret(ctx context.Context, userID, secret string) error {
	secretEncrypted, err := c.encryptValue(secret)
	if err != nil {
		return err
	}
	id, err := gonanoid.New()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Unix()
	_, err = c.db.ExecContext(ctx, `
INSERT INTO user_totp_credentials (id, user_id, secret_encrypted, created_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(user_id) DO UPDATE SET secret_encrypted = excluded.secret_encrypted
`, id, userID, secretEncrypted, now)
	return err
}

func (c *Client) LoadUserTOTPSecret(ctx context.Context, userID string) (string, error) {
	row := c.db.QueryRowContext(ctx, "SELECT secret_encrypted FROM user_totp_credentials WHERE user_id = ?", userID)
	var encrypted string
	if err := row.Scan(&encrypted); err != nil {
		return "", err
	}
	return c.decryptValue(encrypted)
}

func (c *Client) CreateRecoveryCodes(ctx context.Context, userID string) ([]string, error) {
	if _, err := c.db.ExecContext(ctx, "DELETE FROM user_recovery_codes WHERE user_id = ?", userID); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Unix()
	plain := make([]string, 0, c.recoveryCodeCount)
	for i := 0; i < c.recoveryCodeCount; i++ {
		id, _ := gonanoid.New()
		codeRaw, _ := gonanoid.Generate("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 10)
		code := strings.ToUpper(codeRaw)
		h := sha256.Sum256([]byte(code))
		if _, err := c.db.ExecContext(ctx,
			"INSERT INTO user_recovery_codes (id, user_id, code_hash, created_at) VALUES (?, ?, ?, ?)",
			id, userID, h[:], now,
		); err != nil {
			return nil, err
		}
		plain = append(plain, fmt.Sprintf("%s-%s", code[:5], code[5:]))
	}
	return plain, nil
}

func (c *Client) ConsumeRecoveryCode(ctx context.Context, userID, code string) (bool, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(code, "-", ""))
	h := sha256.Sum256([]byte(normalized))
	now := time.Now().UTC().Unix()
	res, err := c.db.ExecContext(ctx,
		"UPDATE user_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
		now, userID, h[:],
	)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

func (c *Client) loadPendingSetup(ctx context.Context, userID, token string) (string, string, error) {
	tokenHash := sha256.Sum256([]byte(token))
	now := time.Now().UTC().Unix()
	row := c.db.QueryRowContext(ctx, `
SELECT id, secret_encrypted
FROM user_totp_pending_setups
WHERE user_id = ? AND token_hash = ? AND expires_at > ?
`, userID, tokenHash[:], now)
	var id string
	var encrypted string
	if err := row.Scan(&id, &encrypted); err != nil {
		return "", "", err
	}
	return id, encrypted, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *Client) encryptValue(plain string) (string, error) {
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plain), nil)
	out := append(nonce, sealed...)
	return base64.RawStdEncoding.EncodeToString(out), nil
}

func (c *Client) decryptValue(ciphertext string) (string, error) {
	raw, err := base64.RawStdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.encryptionKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted value")
	}
	nonce := raw[:gcm.NonceSize()]
	data := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
