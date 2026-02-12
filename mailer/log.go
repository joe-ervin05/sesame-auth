package mailer

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

type LogMailer struct {
	Writer io.Writer
}

func (m LogMailer) Send(_ context.Context, msg Message) error {
	w := m.Writer
	if w == nil {
		w = os.Stdout
	}

	_, err := fmt.Fprintf(
		w,
		"\n---- EMAIL ----\nTo: %s\nSubject: %s\n\n%s\n",
		strings.TrimSpace(msg.To),
		strings.TrimSpace(msg.Subject),
		strings.TrimSpace(msg.TextBody),
	)
	return err
}
