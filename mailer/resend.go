package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ResendConfig struct {
	APIKey      string
	From        string
	BaseURL     string
	HTTPClient  *http.Client
	SendTimeout time.Duration
}

type ResendMailer struct {
	apiKey      string
	from        string
	baseURL     string
	httpClient  *http.Client
	sendTimeout time.Duration
}

func NewResendMailer(cfg ResendConfig) (*ResendMailer, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, errors.New("resend api key is required")
	}
	from := strings.TrimSpace(cfg.From)
	if from == "" {
		return nil, errors.New("resend from address is required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.resend.com"
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &ResendMailer{
		apiKey:      apiKey,
		from:        from,
		baseURL:     baseURL,
		httpClient:  httpClient,
		sendTimeout: cfg.SendTimeout,
	}, nil
}

func (m *ResendMailer) Send(ctx context.Context, msg Message) error {
	sendCtx, cancel := withDefaultSendTimeout(ctx, m.sendTimeout)
	defer cancel()

	to := strings.TrimSpace(msg.To)
	if to == "" {
		return errors.New("email recipient is required")
	}
	subject := strings.TrimSpace(msg.Subject)
	if subject == "" {
		return errors.New("email subject is required")
	}

	payload := map[string]any{
		"from":    m.from,
		"to":      []string{to},
		"subject": subject,
	}
	if strings.TrimSpace(msg.TextBody) != "" {
		payload["text"] = msg.TextBody
	}
	if strings.TrimSpace(msg.HTMLBody) != "" {
		payload["html"] = msg.HTMLBody
	}
	if len(msg.Headers) > 0 {
		payload["headers"] = msg.Headers
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, m.baseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("resend send failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(raw)))
	}

	return nil
}
