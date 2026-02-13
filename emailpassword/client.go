package emailpassword

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/atomicbase/sesame/mailer"
)

type ClientConfig struct {
	DB                           *sql.DB
	Mailer                       mailer.Mailer
	AppName                      string
	AppBaseURL                   string
	Emails                       EmailsConfig
	MinPasswordLength            int
	DisableBreachedPasswordCheck bool
	PasswordBreachCheckTimeout   time.Duration
	PasswordBreachCheckUserAgent string
	PasswordBreachChecker        PasswordBreachChecker
}

type Client struct {
	db             *sql.DB
	mailer         mailer.Mailer
	appName        string
	appBaseURL     string
	emails         EmailsConfig
	passwordPolicy passwordPolicy
}

type passwordPolicy struct {
	minPasswordLength int
	breachChecker     PasswordBreachChecker
}

func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.DB == nil {
		return nil, errors.New("emailpassword client requires db")
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
	if cfg.Emails.ResetPassword == nil {
		cfg.Emails.ResetPassword = DefaultResetPasswordEmailTemplate
	}
	if cfg.Emails.VerifyEmail == nil {
		cfg.Emails.VerifyEmail = DefaultVerifyEmailTemplate
	}

	minPasswordLength := cfg.MinPasswordLength
	if minPasswordLength <= 0 {
		minPasswordLength = 12
	}

	var breachChecker PasswordBreachChecker
	if !cfg.DisableBreachedPasswordCheck {
		if cfg.PasswordBreachChecker != nil {
			breachChecker = cfg.PasswordBreachChecker
		} else {
			breachChecker = NewHIBPPasswordBreachChecker(PasswordBreachCheckConfig{
				Timeout:   cfg.PasswordBreachCheckTimeout,
				UserAgent: cfg.PasswordBreachCheckUserAgent,
			})
		}
	}

	return &Client{
		db:         cfg.DB,
		mailer:     cfg.Mailer,
		appName:    cfg.AppName,
		appBaseURL: strings.TrimRight(cfg.AppBaseURL, "/"),
		emails:     cfg.Emails,
		passwordPolicy: passwordPolicy{
			minPasswordLength: minPasswordLength,
			breachChecker:     breachChecker,
		},
	}, nil
}

func (c *Client) Signup(ctx context.Context, email, password string) (*User, error) {
	return signup(ctx, c.db, email, password, c.passwordPolicy)
}

func (c *Client) Login(ctx context.Context, email, password string) (*User, error) {
	return login(ctx, c.db, email, password)
}

func (c *Client) StartPasswordReset(ctx context.Context, email string) (string, error) {
	userWithPassword, token, err := startPasswordReset(ctx, c.db, email)
	if err != nil {
		return "", err
	}
	if userWithPassword == nil || token == "" {
		return "", nil
	}

	content, err := c.emails.ResetPassword(ResetPasswordTemplateData{
		AppName:     c.appName,
		Email:       userWithPassword.Email,
		ResetURL:    buildResetPasswordURL(c.appBaseURL, token),
		ExpiresIn:   PasswordResetExpiry,
		RequestedAt: time.Now().UTC(),
	})
	if err != nil {
		return "", err
	}

	err = c.mailer.Send(ctx, mailer.Message{
		To:       userWithPassword.Email,
		Subject:  content.Subject,
		TextBody: content.TextBody,
		HTMLBody: content.HTMLBody,
	})
	if err != nil {
		return "", err
	}

	return token, nil
}

func (c *Client) ResetPassword(ctx context.Context, token, newPassword, confirmPassword string) error {
	return resetPassword(ctx, c.db, token, newPassword, confirmPassword, c.passwordPolicy)
}

func (c *Client) ChangePasswordWithConfirmation(ctx context.Context, userID, currentPassword, newPassword, confirmPassword string) error {
	return changePasswordWithConfirmation(ctx, c.db, userID, currentPassword, newPassword, confirmPassword, c.passwordPolicy)
}

func (c *Client) IssueEmailVerificationCode(ctx context.Context, userID string) (string, error) {
	user, code, err := issueEmailVerificationCode(ctx, c.db, userID)
	if err != nil {
		return "", err
	}

	content, err := c.emails.VerifyEmail(VerifyEmailTemplateData{
		AppName:     c.appName,
		Email:       user.Email,
		Code:        code,
		ExpiresIn:   EmailVerificationExpiry,
		RequestedAt: time.Now().UTC(),
	})
	if err != nil {
		return "", err
	}

	err = c.mailer.Send(ctx, mailer.Message{
		To:       user.Email,
		Subject:  content.Subject,
		TextBody: content.TextBody,
		HTMLBody: content.HTMLBody,
	})
	if err != nil {
		return "", err
	}

	return code, nil
}

func (c *Client) VerifyEmailCode(ctx context.Context, userID, code string) error {
	return verifyEmailCode(ctx, c.db, userID, code)
}
