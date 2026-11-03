BIN ?= $(CURDIR)/bin

.PHONY: build test clean

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

clean:
	rm -rf $(BIN) vault/target
