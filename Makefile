.PHONY: build install clean test deps fmt vet dev help uninstall lint check

BINARY_NAME=qfw
CLI_BINARY_NAME=qfw-cli
VERSION=1.0.0
BUILD_DIR=build
INSTALL_PREFIX=/usr/local
CONFIG_DIR=/etc/qfw
SYSTEMD_DIR=/etc/systemd/system
LOG_DIR=/var/log/qfw

# Go build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"
BUILD_FLAGS=-trimpath -mod=readonly

build:
	@echo "Building QFW..."
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/qfw
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(CLI_BINARY_NAME) ./cmd/qfw-cli

install: build
	@echo "Installing QFW..."
	# Install binaries
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_PREFIX)/bin/
	install -m 755 $(BUILD_DIR)/$(CLI_BINARY_NAME) $(INSTALL_PREFIX)/bin/
	
	# Create directories
	mkdir -p $(CONFIG_DIR)
	mkdir -p $(LOG_DIR)
	
	# Install configuration (only if it doesn't exist)
	if [ ! -f $(CONFIG_DIR)/qfw.conf ]; then \
		install -m 644 configs/qfw.conf $(CONFIG_DIR)/; \
	fi
	
	# Install systemd service
	install -m 644 systemd/qfw.service $(SYSTEMD_DIR)/
	systemctl daemon-reload
	
	@echo "Installation complete. Run 'sudo systemctl enable qfw' to enable at boot."

uninstall:
	@echo "Uninstalling QFW..."
	# Stop and disable service
	systemctl stop qfw || true
	systemctl disable qfw || true
	
	# Remove binaries
	rm -f $(INSTALL_PREFIX)/bin/$(BINARY_NAME)
	rm -f $(INSTALL_PREFIX)/bin/$(CLI_BINARY_NAME)
	
	# Remove systemd service
	rm -f $(SYSTEMD_DIR)/qfw.service
	systemctl daemon-reload
	
	@echo "QFW uninstalled. Configuration files in $(CONFIG_DIR) were preserved."

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
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-amd64 ./cmd/qfw
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-linux-amd64 ./cmd/qfw-cli
	
	# Linux arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-arm64 ./cmd/qfw
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/release/$(CLI_BINARY_NAME)-linux-arm64 ./cmd/qfw-cli
	
	@echo "Release binaries built in $(BUILD_DIR)/release/"

dev: build
	@echo "Starting QFW in development mode..."
	@if [ ! -f configs/qfw.conf ]; then \
		echo "Creating default config file..."; \
		mkdir -p configs; \
		echo "[firewall]" > configs/qfw.conf; \
		echo "default_policy=drop" >> configs/qfw.conf; \
		echo "enable_ipv6=false" >> configs/qfw.conf; \
		echo "" >> configs/qfw.conf; \
		echo "[ports]" >> configs/qfw.conf; \
		echo "tcp_in=22,80,443" >> configs/qfw.conf; \
		echo "tcp_out=80,443,53" >> configs/qfw.conf; \
		echo "udp_out=53,123" >> configs/qfw.conf; \
	fi
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qfw.conf -test

debug: build
	@echo "Starting QFW with debug logging..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qfw.conf -test 2>&1 | jq '.'

install-deps:
	@echo "Installing development dependencies..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/tools/cmd/goimports@latest

validate-config:
	@echo "Validating configuration..."
	@if [ -f configs/qfw.conf ]; then \
		$(BUILD_DIR)/$(BINARY_NAME) -config configs/qfw.conf -test -validate; \
	else \
		echo "No config file found at configs/qfw.conf"; \
		exit 1; \
	fi

benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

profile:
	@echo "Running with CPU profiling..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qfw.conf -cpuprofile=cpu.prof

memory-profile:
	@echo "Running with memory profiling..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config configs/qfw.conf -memprofile=mem.prof

status:
	@echo "QFW Service Status:"
	@systemctl is-active qfw || echo "Service not running"
	@echo ""
	@echo "QFW CLI Status:"
	@$(CLI_BINARY_NAME) status 2>/dev/null || echo "Service not responding"

logs:
	@echo "Recent QFW logs:"
	journalctl -u qfw -n 50 --no-pager

help:
	@echo "QFW Makefile Commands:"
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
	@echo "  install       - Install QFW system-wide"
	@echo "  uninstall     - Remove QFW from system"
	@echo ""
	@echo "Operations Commands:"
	@echo "  status        - Show QFW service and API status"
	@echo "  logs          - Show recent QFW logs"
	@echo "  validate-config - Validate configuration file"
	@echo ""
	@echo "  help          - Show this help message"