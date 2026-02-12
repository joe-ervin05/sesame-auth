package mailer

import (
	"context"
	"time"
)

type Message struct {
	To       string
	Subject  string
	TextBody string
	HTMLBody string
	Headers  map[string]string
}

type Content struct {
	Subject  string
	TextBody string
	HTMLBody string
}

type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

type NopMailer struct{}

func (NopMailer) Send(context.Context, Message) error {
	return nil
}

const defaultSendTimeout = 15 * time.Second

func withDefaultSendTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = defaultSendTimeout
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}
