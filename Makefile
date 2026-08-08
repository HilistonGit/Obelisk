BINARY  := obelisk
PKG     := ./cmd/obelisk
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# Every target architecture OpenWrt actually ships on. CGO stays off throughout:
# that is what makes one source tree produce a binary for all of them, and what
# lets the same binary go into both the Docker image and the ipk package.
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm/7 \
	linux/arm/6 \
	linux/mipsle/softfloat \
	linux/mips/softfloat \
	linux/riscv64

.PHONY: all build test vet fmt tidy clean release smoke check

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

# The browser interface is not covered by go test: it is embedded, not compiled.
# smoke runs it under Node against a stub DOM, which is what catches a handler
# that a refactor left dangling — the failure mode there is a blank page and a
# single console line, and only the first missing name is ever reported.
smoke:
	node web/smoke.mjs

check: fmt vet test smoke

# release cross-compiles every target into dist/.
#
# The 32-bit ARM and MIPS targets are built with -tags nosqlite. The pure-Go
# SQLite implementation has no support for them, and dropping those targets
# would cost far more than dropping the traffic history does: they are what a
# large share of routers actually run. Everything except the long-term graphs
# works identically in those builds.
release:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		variant=$$(echo $$platform | cut -d/ -f3); \
		out="dist/$(BINARY)-$$os-$$arch"; \
		env_extra=""; tags=""; \
		case "$$arch" in \
			arm)   env_extra="GOARM=$$variant"; out="$$out"v"$$variant"; tags="-tags nosqlite";; \
			mips|mipsle|mips64|mips64le) env_extra="GOMIPS=$$variant"; tags="-tags nosqlite";; \
		esac; \
		echo "building $$out $$tags"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $$env_extra \
			go build $$tags -trimpath -ldflags "$(LDFLAGS)" -o $$out $(PKG) || exit 1; \
	done
	@ls -lh dist/

clean:
	rm -rf bin dist
