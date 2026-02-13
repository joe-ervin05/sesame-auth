# Sesame Auth

Clean, production-ready auth packages for Go + SQLite.

## SQLite-Only

This library currently supports SQLite only.

- `schema.sql` is the canonical schema contract.
- You are responsible for schema setup and migrations.
- No package touches the schema. They assume it's setup like `schema.sql`.

## Package Guide

### `sessions`

Manages session lifecycle, cookie operations, middleware, and auth-level guards.

We use a split-token for sessions with an id and secret. The secret is hashed for storage.

```
<session_id>.<session_secret>
```

Use it for:

- creating/deleting sessions
- attaching session/user to request context
- enforcing `Primary` vs `Full` auth access

Core methods:

```go
func NewClient(cfg ClientConfig) (*Client, error)
func (c *Client) CreateSession(ctx context.Context, userID string) (string, error)
func (c *Client) CreateSessionWithAuthLevel(ctx context.Context, userID string, authLevel int) (string, error)
func (c *Client) ValidateSession(ctx context.Context, token string) (*Session, *User, error)
func (c *Client) DeleteSession(ctx context.Context, sessionID string) error
func (c *Client) UpgradeSessionToFull(ctx context.Context, sessionID string) error
func (c *Client) DeleteUserSessions(ctx context.Context, userID string) error
func (c *Client) Logout(ctx context.Context) (string, error)
func (c *Client) LogoutHTTP(w http.ResponseWriter, r *http.Request) error
func (c *Client) SetSessionCookie(w http.ResponseWriter, token string)
func (c *Client) ClearSessionCookie(w http.ResponseWriter)
func (c *Client) SessionMiddleware() func(http.Handler) http.Handler
func (c *Client) RequireSession(next http.Handler) http.Handler
func (c *Client) RequireFullSession(next http.Handler) http.Handler
func RequireSameOrigin(allowedOrigin string) func(http.Handler) http.Handler
```

Quick start:

```go
sessionClient, err := sessions.NewClient(sessions.ClientConfig{
    DB: db,
    SessionInactivityTimeout: 10 * 24 * time.Hour,
    SessionActivityCheckInterval: time.Hour,
})
```

### `emailpassword`

Implements email/password signup, login, password reset, change-password, and email verification.

Passwords are hashed using Argon2id and login uses a dummy hash to prevent side-channel attacks.

Use it for:

- credential-based auth
- verification and reset flows
- configurable password policy and breached-password checking

Core methods:

```go
func NewClient(cfg ClientConfig) (*Client, error)
func (c *Client) Signup(ctx context.Context, email, password string) (*User, error)
func (c *Client) Login(ctx context.Context, email, password string) (*User, error)
func (c *Client) StartPasswordReset(ctx context.Context, email string) (string, error)
func (c *Client) ResetPassword(ctx context.Context, token, newPassword, confirmPassword string) error
func (c *Client) ChangePasswordWithConfirmation(ctx context.Context, userID, currentPassword, newPassword, confirmPassword string) error
func (c *Client) IssueEmailVerificationCode(ctx context.Context, userID string) (string, error)
func (c *Client) VerifyEmailCode(ctx context.Context, userID, code string) error
```

Quick start:

```go
emailClient, err := emailpassword.NewClient(emailpassword.ClientConfig{
    DB: db,
    Mailer: mailer.LogMailer{},
    AppName: "My App",
    AppBaseURL: "http://localhost:8080",
    MinPasswordLength: 12,
    DisableBreachedPasswordCheck: false,
})
```

### `emailonly`

Provides passwordless email auth via magic links and one-time passcodes.

Use it for:

- passwordless sign-in
- auto-provisioning users by verified email

Core methods:

```go
func NewClient(cfg ClientConfig) (*Client, error)
func (c *Client) BeginMagicLink(ctx context.Context, email string) (string, error)
func (c *Client) CompleteMagicLink(ctx context.Context, token string) (*User, bool, error)
func (c *Client) BeginOTP(ctx context.Context, email string) (string, error)
func (c *Client) CompleteOTP(ctx context.Context, email, code string) (*User, bool, error)
```

Quick start:

```go
emailOnlyClient, err := emailonly.NewClient(emailonly.ClientConfig{
    DB: db,
    Mailer: mailer.LogMailer{},
    AppName: "My App",
    AppBaseURL: "http://localhost:8080",
})
```

### `oauth`

Handles OAuth provider configuration and callback flows.

We support all OIDC providers out of the box (Google, Microsoft, Facebook, etc) and currently provide custom adapters for:

- GitHub
- Discord
- Reddit
- Shopify
- Spotify
- Twitter

Use it for:

- social/provider sign-in
- provider metadata + callback state handling

Core methods:

```go
func NewClient(cfg ClientConfig) (*Client, error)
func (c *Client) ProviderMetadata() []OAuthProviderMeta
func (c *Client) StartHTTP(w http.ResponseWriter, r *http.Request, providerName string) error
func (c *Client) HandleCallbackHTTP(w http.ResponseWriter, r *http.Request, providerName string) (string, error)
```

Quick start:

```go
oauthClient, err := oauth.NewClient(oauth.ClientConfig{
    DB: db,
    StateSecret: stateSecret,
    Providers: providers,
})
```

### `mfa`

Implements TOTP multi-factor auth and recovery-code workflows.

Use it for:

- TOTP enrollment/challenge
- recovery code generation/consumption

Core methods:

```go
func NewClient(cfg ClientConfig) (*Client, error)
func (c *Client) HasTwoFactorEnabled(ctx context.Context, userID string) (bool, error)
func (c *Client) GenerateTOTPSetup(accountLabel string) (*otp.Key, error)
func (c *Client) VerifyTOTPCode(secret, code string, now time.Time) bool
func (c *Client) StartPendingSetup(ctx context.Context, userID, secret string) (string, error)
func (c *Client) LoadPendingSetupSecret(ctx context.Context, userID, token string) (string, error)
func (c *Client) ConsumePendingSetup(ctx context.Context, userID, token string) (string, error)
func (c *Client) UpsertUserTOTPSecret(ctx context.Context, userID, secret string) error
func (c *Client) LoadUserTOTPSecret(ctx context.Context, userID string) (string, error)
func (c *Client) CreateRecoveryCodes(ctx context.Context, userID string) ([]string, error)
func (c *Client) ConsumeRecoveryCode(ctx context.Context, userID, code string) (bool, error)
```

Quick start:

```go
mfaClient, err := mfa.NewClient(mfa.ClientConfig{
    DB: db,
    EncryptionKey: key32Bytes,
    Issuer: "My App",
})
```

### `passkeys`

Implements WebAuthn registration/login ceremonies and credential persistence helpers.

Use it for:

- passkey enrollment
- passkey authentication

Core methods:

```go
func NewClient(cfg ClientConfig) (*Client, error)
func (c *Client) GetUserByID(ctx context.Context, userID string) (*User, error)
func (c *Client) GetUserByCredentialID(ctx context.Context, credentialID []byte) (*User, error)
func (c *Client) ListUserPasskeys(ctx context.Context, userID string) ([]webauthn.Credential, error)
func (c *Client) SaveUserPasskey(ctx context.Context, userID string, cred *webauthn.Credential) error
func (c *Client) UpdateUserPasskey(ctx context.Context, cred *webauthn.Credential) error
func (c *Client) BeginRegister(ctx context.Context, userID string) (*protocol.CredentialCreation, string, error)
func (c *Client) FinishRegister(ctx context.Context, userID, flowID string, r *protocol.ParsedCredentialCreationData) error
func (c *Client) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
func (c *Client) FinishLogin(ctx context.Context, flowID string, parsed *protocol.ParsedCredentialAssertionData) (string, error)
```

Quick start:

```go
passkeyClient, err := passkeys.NewClient(passkeys.ClientConfig{
    DB: db,
    RPDisplayName: "My App",
    RPID: "localhost",
    RPOrigins: []string{"http://localhost:8080"},
})
```

### `ratelimit`

Provides SQLite token-bucket rate limiting and HTTP helpers.

Use it for:

- endpoint abuse protection
- periodic idle bucket cleanup

Core methods:

```go
func NewTokenBucket(ctx context.Context, db *sql.DB, storageKey string, max int64, refillInterval time.Duration) (*TokenBucket, error)
func (t *TokenBucket) Consume(ctx context.Context, key string, cost int64) (bool, error)
func (t *TokenBucket) PruneIdle(ctx context.Context, maxIdle time.Duration) error
func (t *TokenBucket) StartCleanup(interval, maxIdle time.Duration) func()
func WithRateLimit(limiter Limiter, cost int64, keyFn func(*http.Request) string, next http.Handler) http.Handler
func ClientIP(r *http.Request) string
```

Quick start:

```go
limiter, err := ratelimit.NewTokenBucket(ctx, db, "login:ip", 5, 30*time.Second)
```

### `mailer`

Defines pluggable email transport used by auth packages.

Built-in providers:

- `mailer.LogMailer` for local/dev output
- `mailer.NewSMTPMailer(...)` for SMTP delivery
- `mailer.NewResendMailer(...)` for Resend API delivery

Core methods:

```go
type Mailer interface {
    Send(ctx context.Context, msg Message) error
}

func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error)
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error
func NewResendMailer(cfg ResendConfig) (*ResendMailer, error)
func (m *ResendMailer) Send(ctx context.Context, msg Message) error
func (m LogMailer) Send(ctx context.Context, msg Message) error
func (NopMailer) Send(ctx context.Context, msg Message) error
```

Quick start:

```go
mailClient := mailer.LogMailer{}
```
