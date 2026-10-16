export GOFLAGS=-mod=vendor
export CGO_ENABLED=0
LDF=-trimpath -ldflags="-s -w"

all: relay caller
test:
	go test ./internal/...

# Relay targets
relay: relay-arm64 relay-amd64 relay-armv7 relay-armv6 relay-windows relay-darwin-arm64 relay-darwin-amd64 relay-host

relay-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDF) -o dist/calltunnel-relay-linux-arm64 ./cmd/relay
relay-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDF) -o dist/calltunnel-relay-linux-amd64 ./cmd/relay
relay-armv7:
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDF) -o dist/calltunnel-relay-linux-armv7 ./cmd/relay
relay-armv6:
	GOOS=linux GOARCH=arm GOARM=6 go build $(LDF) -o dist/calltunnel-relay-linux-armv6 ./cmd/relay
relay-windows:
	GOOS=windows GOARCH=amd64 go build $(LDF) -o dist/calltunnel-relay-windows-amd64.exe ./cmd/relay
relay-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(LDF) -o dist/calltunnel-relay-darwin-arm64 ./cmd/relay
relay-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build $(LDF) -o dist/calltunnel-relay-darwin-amd64 ./cmd/relay
relay-host:
	go build $(LDF) -o dist/calltunnel-relay ./cmd/relay

# Caller targets
caller: caller-arm64 caller-amd64 caller-armv7 caller-armv6 caller-windows caller-darwin-arm64 caller-darwin-amd64 caller-host

caller-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDF) -o dist/calltunnel-caller-linux-arm64 ./cmd/caller
caller-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDF) -o dist/calltunnel-caller-linux-amd64 ./cmd/caller
caller-armv7:
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDF) -o dist/calltunnel-caller-linux-armv7 ./cmd/caller
caller-armv6:
	GOOS=linux GOARCH=arm GOARM=6 go build $(LDF) -o dist/calltunnel-caller-linux-armv6 ./cmd/caller
caller-windows:
	GOOS=windows GOARCH=amd64 go build $(LDF) -o dist/calltunnel-caller-windows-amd64.exe ./cmd/caller
caller-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build $(LDF) -o dist/calltunnel-caller-darwin-arm64 ./cmd/caller
caller-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build $(LDF) -o dist/calltunnel-caller-darwin-amd64 ./cmd/caller
caller-host:
	go build $(LDF) -o dist/calltunnel-caller ./cmd/caller

# Combined platform targets
arm64: relay-arm64 caller-arm64
amd64: relay-amd64 caller-amd64
armv7: relay-armv7 caller-armv7
armv6: relay-armv6 caller-armv6
windows: relay-windows caller-windows
darwin: relay-darwin-arm64 relay-darwin-amd64 caller-darwin-arm64 caller-darwin-amd64
host: relay-host caller-host
