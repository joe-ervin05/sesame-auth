package emailpassword

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var version int
	var memory, timeCost uint32
	var threads uint8

	n, _ := fmt.Sscanf(parts[2], "v=%d", &version)
	if n != 1 || version != argon2.Version {
		return false
	}

	n, _ = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads)
	if n != 3 || memory == 0 || timeCost == 0 || threads == 0 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	hash := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(storedHash)))

	return subtle.ConstantTimeCompare(hash, storedHash) == 1
}

var ErrPasswordBreached = errors.New("password found in data breach")

type PasswordBreachChecker func(ctx context.Context, password string) error

type PasswordBreachCheckConfig struct {
	Timeout   time.Duration
	UserAgent string
	Client    *http.Client
}

func NewHIBPPasswordBreachChecker(cfg PasswordBreachCheckConfig) PasswordBreachChecker {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	userAgent := strings.TrimSpace(cfg.UserAgent)
	if userAgent == "" {
		userAgent = "sesame-auth/1.0"
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	return func(ctx context.Context, password string) error {
		hash := sha1.Sum([]byte(password))
		hashHex := strings.ToUpper(hex.EncodeToString(hash[:]))
		prefix := hashHex[:5]
		suffix := hashHex[5:]

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Add-Padding", "true")

		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ":")
			if len(parts) >= 1 && parts[0] == suffix {
				return ErrPasswordBreached
			}
		}
		if err := scanner.Err(); err != nil {
			return nil
		}

		return nil
	}
}

func CheckPasswordBreach(password string) error {
	checker := NewHIBPPasswordBreachChecker(PasswordBreachCheckConfig{})
	return checker(context.Background(), password)
}
