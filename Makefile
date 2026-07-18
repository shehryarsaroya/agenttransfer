# Use a release tag only when HEAD is exactly that release and the worktree is
# clean. `git describe` otherwise resurrects the nearest historical tag (for
# example v0.1.x), while a dirty tagged checkout is not the tagged release.
# Repository tags use a conventional leading "v"; runtime/API versions do not.
VERSION ?= $(shell tag=$$(git describe --tags --exact-match 2>/dev/null); state=$$(git status --porcelain --untracked-files=normal 2>/dev/null); if [ -n "$$tag" ] && [ -z "$$state" ]; then printf '%s\n' "$$tag" | sed 's/^v//'; else echo 0.7.0-dev; fi)
LDFLAGS  = -s -w -X github.com/shehryarsaroya/agenttransfer/internal/server.Version=$(VERSION)

.PHONY: version build test demo lint clean release

version:
	@printf '%s\n' '$(VERSION)'

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
