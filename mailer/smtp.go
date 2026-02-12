package mailer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	From        string
	FromName    string
	SendTimeout time.Duration
}

type SMTPMailer struct {
	host        string
	port        int
	username    string
	password    string
	from        mail.Address
	sendTimeout time.Duration
}

func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	host := strings.TrimSpace(cfg.Host)
	if host == "" {
		return nil, errors.New("smtp host is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	if strings.TrimSpace(cfg.From) == "" {
		return nil, errors.New("smtp from address is required")
	}

	from := mail.Address{Name: strings.TrimSpace(cfg.FromName), Address: strings.TrimSpace(cfg.From)}
	if _, err := mail.ParseAddress(from.String()); err != nil {
		return nil, fmt.Errorf("invalid smtp from address: %w", err)
	}

	return &SMTPMailer{
		host:        host,
		port:        cfg.Port,
		username:    strings.TrimSpace(cfg.Username),
		password:    cfg.Password,
		from:        from,
		sendTimeout: cfg.SendTimeout,
	}, nil
}

func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	sendCtx, cancel := withDefaultSendTimeout(ctx, m.sendTimeout)
	defer cancel()

	if err := sendCtx.Err(); err != nil {
		return err
	}

	toAddr, toHeader, err := parseRecipient(msg.To)
	if err != nil {
		return err
	}

	subject := sanitizeHeader(msg.Subject)
	if subject == "" {
		return errors.New("email subject is required")
	}

	body := buildMIMEBody(m.from.String(), toHeader, subject, msg)
	addr := fmt.Sprintf("%s:%d", m.host, m.port)

	var auth smtp.Auth
	if m.username != "" {
		auth = smtp.PlainAuth("", m.username, m.password, m.host)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- smtp.SendMail(addr, auth, m.from.Address, []string{toAddr}, body)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
		return sendCtx.Err()
	case <-sendCtx.Done():
		return sendCtx.Err()
	}
}

func parseRecipient(input string) (envelopeTo string, headerTo string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", errors.New("email recipient is required")
	}

	addr, parseErr := mail.ParseAddress(input)
	if parseErr == nil {
		return addr.Address, addr.String(), nil
	}

	if strings.ContainsAny(input, "\r\n") {
		return "", "", errors.New("invalid recipient header")
	}

	if _, err := mail.ParseAddress(input); err != nil {
		if !strings.Contains(input, "@") {
			return "", "", errors.New("invalid recipient email")
		}
	}

	return input, input, nil
}

func buildMIMEBody(from, to, subject string, msg Message) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + sanitizeHeader(from) + "\r\n")
	b.WriteString("To: " + sanitizeHeader(to) + "\r\n")
	b.WriteString("Subject: " + sanitizeHeader(subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	for k, v := range msg.Headers {
		key := sanitizeHeader(k)
		if key == "" {
			continue
		}
		switch strings.ToLower(key) {
		case "from", "to", "subject", "mime-version", "content-type":
			continue
		}
		b.WriteString(key + ": " + sanitizeHeader(v) + "\r\n")
	}

	text := strings.TrimSpace(msg.TextBody)
	html := strings.TrimSpace(msg.HTMLBody)

	if text != "" && html != "" {
		boundary := fmt.Sprintf("sesame-%d", time.Now().UnixNano())
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(text + "\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		b.WriteString(html + "\r\n")
		b.WriteString("--" + boundary + "--\r\n")
		return b.Bytes()
	}

	if html != "" {
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		b.WriteString(html + "\r\n")
		return b.Bytes()
	}

	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(text + "\r\n")
	return b.Bytes()
}

func sanitizeHeader(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}
