package emailpassword

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/atomicbase/sesame/mailer"
)

type ResetPasswordTemplateData struct {
	AppName     string
	Email       string
	ResetURL    string
	ExpiresIn   time.Duration
	RequestedAt time.Time
}

type VerifyEmailTemplateData struct {
	AppName     string
	Email       string
	Code        string
	ExpiresIn   time.Duration
	RequestedAt time.Time
}

type ResetPasswordTemplate func(data ResetPasswordTemplateData) (mailer.Content, error)
type VerifyEmailTemplate func(data VerifyEmailTemplateData) (mailer.Content, error)

type EmailsConfig struct {
	ResetPassword ResetPasswordTemplate
	VerifyEmail   VerifyEmailTemplate
}

func DefaultResetPasswordEmailTemplate(data ResetPasswordTemplateData) (mailer.Content, error) {
	appName := strings.TrimSpace(data.AppName)
	if appName == "" {
		appName = "Sesame"
	}

	return mailer.Content{
		Subject: fmt.Sprintf("%s password reset", appName),
		TextBody: fmt.Sprintf(
			"Use this link to reset your password: %s\n\nThis link expires in %s.",
			data.ResetURL,
			data.ExpiresIn.Round(time.Minute).String(),
		),
		HTMLBody: fmt.Sprintf(
			"<p>Use this link to reset your password:</p><p><a href=\"%s\">Reset password</a></p><p>This link expires in %s.</p>",
			data.ResetURL,
			data.ExpiresIn.Round(time.Minute).String(),
		),
	}, nil
}

func DefaultVerifyEmailTemplate(data VerifyEmailTemplateData) (mailer.Content, error) {
	appName := strings.TrimSpace(data.AppName)
	if appName == "" {
		appName = "Sesame"
	}

	return mailer.Content{
		Subject: fmt.Sprintf("%s email verification code", appName),
		TextBody: fmt.Sprintf(
			"Your verification code is: %s\n\nThis code expires in %s.",
			data.Code,
			data.ExpiresIn.Round(time.Minute).String(),
		),
		HTMLBody: fmt.Sprintf(
			"<p>Your verification code is:</p><p><strong>%s</strong></p><p>This code expires in %s.</p>",
			data.Code,
			data.ExpiresIn.Round(time.Minute).String(),
		),
	}, nil
}

func buildResetPasswordURL(appBaseURL, token string) string {
	base := strings.TrimRight(strings.TrimSpace(appBaseURL), "/")
	if base == "" {
		base = "http://localhost:8080"
	}
	return fmt.Sprintf("%s/reset-password?token=%s", base, url.QueryEscape(token))
}
