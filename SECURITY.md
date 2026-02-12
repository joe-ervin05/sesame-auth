# Security Notes

## Auth Levels

`sessions` supports two auth levels:

- `Primary`: user has completed first-factor auth
- `Full`: user has completed all required factors

Use `RequirePrimarySession` and `RequireFullSession` to gate routes by sensitivity.

## MFA and Passkeys

- TOTP MFA is managed by `mfa` and should be enforced when configured.
- Passkeys are managed by `passkeys` and can be used as an authentication factor.
- Session auth level should be upgraded to `Full` only after required checks complete.

## WebAuthn Configuration

When using `passkeys`, RP settings must match the real deployment origin:

- RP ID
- RP origin(s)

Origin/host mismatches will break registration or authentication.

## Operational Guidance

- Keep dependencies updated.
- Protect secrets (OAuth secrets, mail API keys, encryption keys).
- Use strict origin checks for state-changing requests.
- Apply rate limits to login, callback, and challenge endpoints.
- Prefer secure cookies (`HttpOnly`, `Secure` in production).

## Reporting

If you find a security issue, please open a private report to the maintainer instead of filing a public issue with exploit details.
