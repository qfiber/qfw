.PHONY: build install clean test deps fmt vet dev help uninstall lint check

BINARY_NAME=qff
CLI_BINARY_NAME=qff-cli
VERSION=1.0.0
BUILD_DIR=build
INSTALL_PREFIX=/usr/local
CONFIG_DIR=/etc/qff
SYSTEMD_DIR=/etc/systemd/system
LOG_DIR=/var/log/qff

# Go build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"
BUILD_FLAGS=-trimpath -mod=readonly

build:
	@echo "Building QFF..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qff
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_BINARY_NAME) ./cmd/qff-cli

install: build
	@echo "Installing QFF..."
	# Install binaries
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PREFIX)/bin/
	install -m 755 $(BUILD_DIR)/$(CLI_BINARY_NAME) $(INSTALL_PREFIX)/bin/
	
	# Create directories
	mkdir -p $(CONFIG_DIR)
	mkdir -p $(LOG_DIR)
	
	# Install configuration (only if it doesn't exist)
	if [ ! -f $(CONFIG_DIR)/qff.conf ]; then \
		install -m 644 configs/qff.conf $(CONFIG_DIR)/; \
	fi
	
	# Install systemd service
	install -m 644 systemd/qff.service $(SYSTEMD_DIR)/
	systemctl daemon-reload
	
	@echo "Installation complete. Run 'sudo systemctl enable qff' to enable at boot."

uninstall:
	@echo "Uninstalling QFF..."
	# Stop and disable service
	systemctl stop qff || true
	systemctl disable qff || true
	
	# Remove binaries
	rm -f $(INSTALL_PREFIX)/bin/$(BINARY_NAME)
	rm -f $(INSTALL_PREFIX)/bin/$(CLI_BINARY_NAME)
	
	# Remove systemd service
	rm -f $(SYSTEMD_DIR)/qff.service
	systemctl daemon-reload
	
	@echo "QFF uninstalled. Configuration files in $(CONFIG_DIR) were preserved."

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	go clean -cache

test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-integration:
	@echo "Running integration tests..."
	go test -v -tags=integration ./...

lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

fmt:
	@echo "Formatting code..."
	go fmt ./...
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

vet:
	@echo "Running go vet..."
	go vet ./...

check: fmt vet lint test
	@echo "All checks passed!"

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	go mod verify

deps-update:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

release: check
	@echo "Building release binaries..."
	mkdir -p $(BUILD_DIR)/release
	
	# Linux amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-amd64 ./cmd/qff
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-linux-amd64 ./cmd/qff-cli
	
	# Linux arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-arm64 ./cmd/qff
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-linux-arm64 ./cmd/qff-cli
	
	@echo "Release binaries built in $(BUILD_DIR)/release/"

dev: build
	@echo "Starting QFF in development mode..."
	@if [ ! -f configs/qff.conf ]; then \
		echo "Creating default config file..."; \
		mkdir -p configs; \
		echo "[firewall]" > configs/qff.conf; \
		echo "default_policy=drop" >> configs/qff.conf; \
		echo "enable_ipv6=false" >> configs/qff.conf; \
		echo "" >> configs/qff.conf; \
		echo "[ports]" >> configs/qff.conf; \
		echo "tcp_in=22,80,443" >> configs/qff.conf; \
		echo "tcp_out=80,443,53" >> configs/qff.conf; \
		echo "udp_out=53,123" >> configs/qff.conf; \
	fi
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qff.conf -test

debug: build
	@echo "Starting QFF with debug logging..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qff.conf -test 2>&1 | jq '.'

install-deps:
	@echo "Installing development dependencies..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

validate-config:
	@echo "Validating configuration..."
	@if [ -f configs/qff.conf ]; then \
		$(BUILD_DIR)/$(BINARY_NAME) -config configs/qff.conf -test -validate; \
	else \
		echo "No config file found at configs/qff.conf"; \
		exit 1; \
	fi

benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

profile:
	@echo "Running with CPU profiling..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qff.conf -cpuprofile=cpu.prof

memory-profile:
	@echo "Running with memory profiling..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qff.conf -memprofile=mem.prof

status:
	@echo "QFF Service Status:"
	@systemctl is-active qff || echo "Service not running"
	@echo ""
	@echo "QFF CLI Status:"
	@$(CLI_BINARY_NAME) status 2>/dev/null || echo "Service not responding"

logs:
	@echo "Recent QFF logs:"
	journalctl -u qff -n 50 --no-pager

help:
	@echo "QFF Makefile Commands:"
	@echo ""
	@echo "Build Commands:"
	@echo "  build         - Build the binaries"
	@echo "  release       - Build release binaries for multiple platforms"
	@echo "  clean         - Clean build artifacts"
	@echo ""
	@echo "Development Commands:"
	@echo "  dev           - Build and run in development mode"
	@echo "  debug         - Run with debug logging and JSON formatting"
	@echo "  test          - Run unit tests with coverage"
	@echo "  test-integration - Run integration tests"
	@echo "  benchmark     - Run performance benchmarks"
	@echo "  profile       - Run with CPU profiling"
	@echo "  memory-profile - Run with memory profiling"
	@echo ""
	@echo "Code Quality Commands:"
	@echo "  fmt           - Format Go code"
	@echo "  vet           - Run go vet"
	@echo "  lint          - Run golangci-lint"
	@echo "  check         - Run all quality checks (fmt, vet, lint, test)"
	@echo ""
	@echo "Dependency Commands:"
	@echo "  deps          - Download and verify dependencies"
	@echo "  deps-update   - Update all dependencies"
	@echo "  install-deps  - Install development tools"
	@echo ""
	@echo "Installation Commands:"
	@echo "  install       - Install QFF system-wide"
	@echo "  uninstall     - Remove QFF from system"
	@echo ""
	@echo "Operations Commands:"
	@echo "  status        - Show QFF service and API status"
	@echo "  logs          - Show recent QFF logs"
	@echo "  validate-config - Validate configuration file"
	@echo ""
	@echo "  help          - Show this help message"