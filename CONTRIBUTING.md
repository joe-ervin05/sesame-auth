# Contributing

Thanks for your interest in contributing.

## Development

- Go version: follow `go.mod`
- Database backend: SQLite

Typical workflow:

1. Create a branch for your change.
2. Run `go test ./...` before opening a PR.
3. Keep changes package-focused and avoid introducing app/demo-only code.

## Scope Guidelines

- Keep this repository as a reusable library.
- Do not add example server handlers/routes in this repo.
- Prefer constructor-driven configuration (`NewClient(Config)`).

## Pull Requests

- Include a clear problem statement and rationale.
- Keep commits and diffs focused.
- Add or update tests when behavior changes.
