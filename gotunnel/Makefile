export GOFLAGS=-mod=vendor
export CGO_ENABLED=0
LDF=-trimpath -ldflags="-s -w"

all: arm64 armv7 armv6
test:
	go test ./internal/...
arm64:
	GOOS=linux GOARCH=arm64 go build $(LDF) -o dist/calltunnel-relay-linux-arm64 ./cmd/relay
armv7:
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDF) -o dist/calltunnel-relay-linux-armv7 ./cmd/relay
armv6:
	GOOS=linux GOARCH=arm GOARM=6 go build $(LDF) -o dist/calltunnel-relay-linux-armv6 ./cmd/relay
host:
	go build $(LDF) -o dist/calltunnel-relay ./cmd/relay
