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

Use it for:

- creating/deleting sessions
- attaching session/user to request context
- enforcing `Primary` vs `Full` auth access

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

Use it for:

- credential-based auth
- verification and reset flows
- configurable password policy and breached-password checking

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

Handles OAuth provider configuration and callback flow orchestration.

Use it for:

- social/provider sign-in
- provider metadata + callback state handling

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

Quick start:

```go
limiter, err := ratelimit.NewTokenBucketRateLimit(ctx, db, "login:ip", 5, 30*time.Second)
```

### `mailer`

Defines pluggable email transport used by auth packages.

Built-in providers:

- `mailer.LogMailer` for local/dev output
- `mailer.NewSMTPMailer(...)` for SMTP delivery
- `mailer.NewResendMailer(...)` for Resend API delivery

Quick start:

```go
mailClient := mailer.LogMailer{}
```

## Notes

- No framework-specific handlers are included in this repository.
- Remaining HTTP helpers are package-level middleware/guard primitives.
