VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS  = -s -w -X github.com/shehryarsaroya/agenttransfer/internal/server.Version=$(VERSION)

.PHONY: build test demo lint clean release

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o agenttransfer .

test:
	go test ./...

demo: build
	./agenttransfer demo

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed on:" && gofmt -l . && exit 1)
	go vet ./...

clean:
	rm -f agenttransfer
	rm -rf dist

# static binaries for the usual platforms
release:
	mkdir -p dist
	GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/agenttransfer-linux-amd64 .
	GOOS=linux  GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/agenttransfer-linux-arm64 .
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/agenttransfer-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/agenttransfer-darwin-amd64 .
