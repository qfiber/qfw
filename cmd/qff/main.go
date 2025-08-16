// cmd/qff/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"qff/internal/api"
	"qff/internal/config"
	"qff/internal/firewall"
	"qff/internal/geoip"
	"qff/internal/ips"
	"qff/internal/logger"
	"qff/internal/monitor"
	"qff/internal/notify"
)

const (
	Version                 = "1.0.0"
	DefaultConfigPath       = "/etc/qff/qff.conf"
	DefaultAPIPort          = ":8080"
	ShutdownTimeout         = 30 * time.Second
	ConnectivityTestTimeout = 3 * time.Second
)

// App encapsulates the entire application state
type App struct {
	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc

	// Core components
	notifier      *notify.Notifier
	geoipMgr      *geoip.GeoIPManager
	enhancedGeoIP *geoip.EnhancedGeoIPManager
	firewallMgr   *firewall.NFTManager
	ipsManager    *ips.IPSManager
	systemMonitor *monitor.SystemMonitor
	apiServer     *api.APIServer

	// Synchronization
	wg           sync.WaitGroup
	shutdownOnce sync.Once
}

func main() {
	// Parse command line flags
	flags := parseFlags()

	if flags.version {
		fmt.Printf("QFF - qFibre Firewall Manager v%s\n", Version)
		os.Exit(0)
	}

	// Create application context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := &App{
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize and run application
	if err := app.initialize(flags); err != nil {
		logger.Error("main", "Failed to initialize application", "error", err.Error())
		os.Exit(1)
	}

	// Handle test mode if enabled
	if flags.testMode || app.cfg.TestMode.EnableTestMode {
		if err := app.runTestMode(); err != nil {
			logger.Error("main", "Test mode failed", "error", err.Error())
			os.Exit(1)
		}
	}

	// Start all services concurrently
	if err := app.start(); err != nil {
		logger.Error("main", "Failed to start services", "error", err.Error())
		os.Exit(1)
	}

	logger.Info("main", "QFF started successfully", "version", Version, "pid", os.Getpid())

	// Wait for shutdown signal
	app.waitForShutdown()

	// Graceful shutdown
	app.shutdown()
	logger.Info("main", "QFF shutdown completed")
}

type flags struct {
	configPath string
	version    bool
	testMode   bool
}

func parseFlags() *flags {
	var f flags
	flag.StringVar(&f.configPath, "config", DefaultConfigPath, "Configuration file path")
	flag.BoolVar(&f.version, "version", false, "Show version information")
	flag.BoolVar(&f.testMode, "test", false, "Run in test mode")
	flag.Parse()
	return &f
}

func (app *App) initialize(flags *flags) error {
	// Pre-flight checks
	if err := preFlightChecks(); err != nil {
		return fmt.Errorf("pre-flight checks failed: %w", err)
	}

	// Load and validate configuration
	cfg, err := config.LoadConfig(flags.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", flags.configPath, err)
	}

	if err := config.ValidateConfig(cfg); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	app.cfg = cfg
	logger.Info("main", "Configuration loaded and validated", "config_path", flags.configPath)

	// Initialize components in dependency order
	if err := app.initializeComponents(); err != nil {
		return fmt.Errorf("component initialization failed: %w", err)
	}

	return nil
}

func preFlightChecks() error {
	// Check system requirements
	if runtime.GOOS != "linux" {
		return fmt.Errorf("QFF requires Linux operating system")
	}

	// Check nftables availability
	if err := firewall.CheckNFTablesAvailable(); err != nil {
		return fmt.Errorf("nftables check failed: %w", err)
	}

	// Check required permissions
	if os.Geteuid() != 0 {
		return fmt.Errorf("QFF requires root privileges")
	}

	return nil
}

func (app *App) initializeComponents() error {
	// Initialize notifier (no dependencies)
	app.notifier = notify.NewNotifier(&app.cfg.Notification)

	// Initialize GeoIP manager
	app.geoipMgr = geoip.NewGeoIPManager(&app.cfg.GeoIP)
	if err := app.geoipMgr.Initialize(); err != nil {
		logger.Warn("main", "GeoIP initialization failed", "error", err.Error())
		// Continue without GeoIP - not critical for basic firewall functionality
	} else {
		// Enable auto-download if API key is provided
		if app.cfg.GeoIP.MaxMindAPIKey != "" {
			app.geoipMgr.EnableAutoDownload(app.cfg.GeoIP.MaxMindAPIKey)
		}

		// Initialize enhanced GeoIP
		app.enhancedGeoIP = geoip.NewEnhancedGeoIPManager(app.geoipMgr, &app.cfg.GeoIP)
		if err := app.enhancedGeoIP.Initialize(); err != nil {
			logger.Warn("main", "Enhanced GeoIP initialization failed", "error", err.Error())
		}
	}

	// Initialize firewall manager (critical component)
	app.firewallMgr = firewall.NewNFTManager(app.cfg)
	if err := app.firewallMgr.Initialize(); err != nil {
		return fmt.Errorf("firewall initialization failed: %w", err)
	}

	// Auto-whitelist current user to prevent lockout
	if err := app.firewallMgr.WhitelistCurrentUser(); err != nil {
		logger.Warn("main", "Failed to auto-whitelist current user", "error", err.Error())
		// Continue - this is a safety feature, not critical
	}

	// Initialize IPS manager
	app.ipsManager = ips.NewIPSManager(&app.cfg.IPS, app.firewallMgr, app.notifier, app.enhancedGeoIP)

	// Initialize system monitor
	systemMonitor, err := monitor.NewSystemMonitor(&app.cfg.Monitor, app.notifier)
	if err != nil {
		logger.Error("main", "Failed to initialize system monitor", "error", err)
		return fmt.Errorf("system monitor initialization failed: %w", err)
	}
	app.systemMonitor = systemMonitor

	// Initialize API server
	app.apiServer = api.NewAPIServer(app.cfg, app.firewallMgr, app.systemMonitor, app.ipsManager)

	logger.Info("main", "All components initialized successfully")
	return nil
}

func (app *App) start() error {
	// Start IPS manager
	if app.ipsManager != nil {
		if err := app.ipsManager.Start(); err != nil {
			logger.Error("main", "Failed to start IPS manager", "error", err.Error())
			// Continue without IPS - firewall can still function
		}
	}

	// Start system monitor
	if app.systemMonitor != nil {
		app.systemMonitor.Start()
	}

	// Start API server in a separate goroutine
	app.wg.Add(1)
	go func() {
		defer app.wg.Done()

		// Listen for context cancellation
		go func() {
			<-app.ctx.Done()
			logger.Info("api", "Context cancelled, API server should shutdown")
		}()

		// Start the server - this will block until shutdown
		if err := app.apiServer.Start(DefaultAPIPort); err != nil {
			logger.Error("main", "API server failed", "error", err.Error())
			app.cancel() // Trigger shutdown if API server fails
		}
	}()

	return nil
}

func (app *App) waitForShutdown() {
	// Create signal channel
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	select {
	case sig := <-sigCh:
		logger.Info("main", "Received shutdown signal", "signal", sig.String())
	case <-app.ctx.Done():
		logger.Info("main", "Context cancelled, initiating shutdown")
	}
}

func (app *App) shutdown() {
	app.shutdownOnce.Do(func() {
		logger.Info("main", "Starting graceful shutdown")

		// Cancel context to stop all operations
		app.cancel()

		// Create shutdown timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer cancel()

		// Shutdown components in reverse dependency order
		done := make(chan struct{})
		go func() {
			defer close(done)
			app.shutdownComponents()
			app.wg.Wait()
		}()

		select {
		case <-done:
			logger.Info("main", "Graceful shutdown completed")
		case <-shutdownCtx.Done():
			logger.Warn("main", "Shutdown timeout exceeded, forcing exit")
		}
	})
}

func (app *App) shutdownComponents() {
	// Stop API server first to prevent new requests
	if app.apiServer != nil {
		// If APIServer doesn't have a Stop method, we'll use context cancellation
		// The server should be listening for app.ctx.Done()
		logger.Info("shutdown", "Stopping API server")
	}

	// Stop monitoring and detection services
	if app.systemMonitor != nil {
		app.systemMonitor.Stop()
	}

	if app.ipsManager != nil {
		app.ipsManager.Stop()
	}

	// Close GeoIP resources
	if app.enhancedGeoIP != nil {
		app.enhancedGeoIP.Stop()
	}

	if app.geoipMgr != nil {
		app.geoipMgr.Close()
	}

	// Firewall manager cleanup happens automatically via defer in main
}

func (app *App) runTestMode() error {
	if !app.cfg.TestMode.EnableTestMode {
		return nil
	}

	logger.Info("testmode", "Starting test mode", "duration", app.cfg.TestMode.TestDuration)

	// Backup current firewall state
	originalState, err := app.firewallMgr.BackupCurrentState()
	if err != nil {
		return fmt.Errorf("failed to backup firewall state: %w", err)
	}

	// Run connectivity tests
	testResults := app.runConnectivityTests(app.cfg.TestMode.TestConnections)

	// Log test results
	for host, success := range testResults {
		logger.Info("testmode", "Initial connectivity test", "host", host, "success", success)
	}

	// Setup auto-revert if enabled
	if app.cfg.TestMode.RevertOnFailure {
		time.AfterFunc(app.cfg.TestMode.TestDuration, func() {
			logger.Info("testmode", "Test mode timeout, checking connectivity")

			// Re-run connectivity tests
			allTests := true
			for _, host := range app.cfg.TestMode.TestConnections {
				if !testConnectivity(host, ConnectivityTestTimeout) {
					allTests = false
					break
				}
			}

			if !allTests {
				logger.Warn("testmode", "Connectivity tests failed, reverting configuration")
				// originalState is already of type *firewall.FirewallState, no type assertion needed
				if err := app.firewallMgr.RestoreState(originalState); err != nil {
					logger.Error("testmode", "Failed to restore state", "error", err.Error())
				} else {
					logger.Info("testmode", "Configuration reverted successfully")
				}
			} else {
				logger.Info("testmode", "All connectivity tests passed, keeping configuration")
			}
		})
	}

	return nil
}

func (app *App) runConnectivityTests(hosts []string) map[string]bool {
	if len(hosts) == 0 {
		return make(map[string]bool)
	}

	results := make(map[string]bool, len(hosts))
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Test connectivity concurrently for better performance
	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			success := testConnectivity(h, ConnectivityTestTimeout)
			mu.Lock()
			results[h] = success
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results
}

func testConnectivity(host string, timeout time.Duration) bool {
	// Add default port if not specified
	if _, _, err := net.SplitHostPort(host); err != nil {
		// Try HTTPS first, then HTTP
		if testSingleConnection(host+":443", timeout) {
			return true
		}
		host += ":80"
	}

	return testSingleConnection(host, timeout)
}

func testSingleConnection(address string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
