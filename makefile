
test:
	@CGO_ENABLED=1 go test ./... -tags fts5

tidy:
	@go mod tidy
