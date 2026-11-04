BIN ?= $(CURDIR)/bin
DIST ?= $(CURDIR)/dist
VERSION := $(shell sed -n 's/^const version = "\(.*\)"/\1/p' cli/cmd/cervus/main.go)

.PHONY: build test clean version dist test-dist

build:
	mkdir -p $(BIN)
	cd vault && cargo build --release && cp target/release/cervus-vault $(BIN)/
	cd cli && go build -o $(BIN)/cervus ./cmd/cervus && go build -o $(BIN)/cervusd ./cmd/cervusd

test: build
	cd vault && cargo test
	cd cli && go vet ./... && go test ./...
	BIN=$(BIN) bash ./scripts/e2e.sh
	BIN=$(BIN) bash ./scripts/e2e_aws.sh
	BIN=$(BIN) bash ./scripts/e2e_migrate.sh
	BIN=$(BIN) ZSH=$$(command -v zsh) bash ./scripts/e2e_shell.sh

version:
	@echo $(VERSION)

# A release archive for this machine's OS and architecture.
dist:
	set -e; \
	name=cervus-$(VERSION)-$$(cd cli && go env GOOS)-$$(cd cli && go env GOARCH); \
	dir="$(DIST)/$$name"; \
	rm -rf "$$dir"; mkdir -p "$$dir"; \
	(cd vault && cargo build --release --locked && cp target/release/cervus-vault "$$dir/"); \
	(cd cli && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$$dir/cervus" ./cmd/cervus); \
	(cd cli && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$$dir/cervusd" ./cmd/cervusd); \
	cp LICENSE README.md "$$dir/"; \
	tar -C "$(DIST)" -czf "$(DIST)/$$name.tar.gz" "$$name"; \
	rm -rf "$$dir"

test-dist:
	bash ./scripts/test_dist.sh

clean:
	rm -rf $(BIN) $(DIST) vault/target
