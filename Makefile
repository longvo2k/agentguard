VERSION ?= 0.1.0
BIN     := bin/agentguard
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build install test test-short test-docker lint demo clean image

build: ## Build the agentguard binary into bin/
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/agentguard

install: ## Install agentguard into $GOPATH/bin
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/agentguard

test: ## All tests; Docker tests run when a daemon is available
	go test ./...

test-short: ## Unit tests only, no Docker
	go test -short ./...

test-docker: ## Docker integration tests (set AGENTGUARD_TEST_IMAGE to reuse an image)
	go test -count=1 -run 'Sandbox|Docker' -v ./internal/sandbox ./tests

lint: ## gofmt + go vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

image: ## Build the default sandbox image
	docker build -t agentguard-sandbox:0.1 - < internal/sandbox/Dockerfile

demo: build ## Run the demo
	./$(BIN) demo

clean:
	rm -rf bin/
