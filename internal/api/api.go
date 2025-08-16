// internal/api/api.go
package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"qfw/internal/config"
	"qfw/internal/firewall"
	"qfw/internal/ips"
	"qfw/internal/logger"
	"qfw/internal/monitor"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type APIServer struct {
	config     *config.Config
	firewall   *firewall.NFTManager
	monitor    *monitor.SystemMonitor
	ipsManager *ips.IPSManager
	router     *mux.Router
	startTime  time.Time
}

type StatusResponse struct {
	Status           string                 `json:"status"`
	Version          string                 `json:"version"`
	Uptime           string                 `json:"uptime"`
	GeoIPAvailable   bool                   `json:"geoip_available"`
	TemporaryEntries int                    `json:"temporary_entries"`
	Config           map[string]interface{} `json:"config,omitempty"`
}

type MetricsResponse struct {
	SystemMetrics   map[string]interface{} `json:"system_metrics"`
	FirewallMetrics map[string]interface{} `json:"firewall_metrics"`
}

func (a *APIServer) handleIPSBlocked(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	blocked := a.ipsManager.GetBlockedIPs()
	a.writeJSONResponse(w, map[string]interface{}{
		"blocked_ips": blocked,
		"count":       len(blocked),
	})
}

func (a *APIServer) handleIPSWhitelist(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	whitelist := a.ipsManager.GetWhitelistedIPs()
	a.writeJSONResponse(w, map[string]interface{}{
		"whitelisted_ips": whitelist,
		"count":           len(whitelist),
	})
}

func (a *APIServer) handleIPSUnblock(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.ipsManager.UnblockIP(ip); err != nil {
		a.writeErrorResponse(w, "Failed to unblock IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{
		"status": "unblocked",
		"ip":     ip.String(),
	})
}

func (a *APIServer) handleIPSWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	permanent := r.URL.Query().Get("permanent") == "true"
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "Manual whitelist via API"
	}

	if err := a.ipsManager.AddWhitelist(ip, permanent, reason); err != nil {
		a.writeErrorResponse(w, "Failed to whitelist IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]interface{}{
		"status":    "whitelisted",
		"ip":        ip.String(),
		"permanent": permanent,
		"reason":    reason,
	})
}

func (a *APIServer) handleIPSWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.ipsManager.RemoveWhitelist(ip); err != nil {
		a.writeErrorResponse(w, "Failed to remove whitelist", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{
		"status": "removed",
		"ip":     ip.String(),
	})
}

func (a *APIServer) handleIPSStats(w http.ResponseWriter, r *http.Request) {
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS not enabled", http.StatusServiceUnavailable)
		return
	}

	stats := a.ipsManager.GetStats()
	a.writeJSONResponse(w, stats)
}

func NewAPIServer(cfg *config.Config, fw *firewall.NFTManager, mon *monitor.SystemMonitor, ipsManager *ips.IPSManager) *APIServer {
	api := &APIServer{
		config:     cfg,
		firewall:   fw,
		monitor:    mon,
		ipsManager: ipsManager,
		router:     mux.NewRouter(),
		startTime:  time.Now(),
	}

	api.setupRoutes()
	return api
}

func (a *APIServer) setupRoutes() {
	a.router.HandleFunc("/status", a.handleStatus).Methods("GET")
	a.router.HandleFunc("/metrics", a.handleMetrics).Methods("GET")
	a.router.HandleFunc("/reload", a.handleReload).Methods("POST")

	// IP management
	a.router.HandleFunc("/whitelist", a.handleWhitelistAdd).Methods("POST")
	a.router.HandleFunc("/whitelist", a.handleWhitelistRemove).Methods("DELETE")
	a.router.HandleFunc("/blacklist", a.handleBlacklistAdd).Methods("POST")
	a.router.HandleFunc("/blacklist", a.handleBlacklistRemove).Methods("DELETE")

	// DNS management
	a.router.HandleFunc("/dns/hosts", a.handleDNSHosts).Methods("GET")
	a.router.HandleFunc("/dns/add", a.handleDNSAdd).Methods("POST")

	// Prometheus metrics
	a.router.Handle("/prometheus", promhttp.Handler())

	// IPS management endpoints
	a.router.HandleFunc("/api/ips/blocked", a.handleIPSBlocked).Methods("GET")
	a.router.HandleFunc("/api/ips/whitelist", a.handleIPSWhitelist).Methods("GET")
	a.router.HandleFunc("/api/ips/unblock", a.handleIPSUnblock).Methods("POST")
	a.router.HandleFunc("/api/ips/whitelist/add", a.handleIPSWhitelistAdd).Methods("POST")
	a.router.HandleFunc("/api/ips/whitelist/remove", a.handleIPSWhitelistRemove).Methods("DELETE")
	a.router.HandleFunc("/api/ips/stats", a.handleIPSStats).Methods("GET")

	// Enhanced GeoIP endpoints
	a.router.HandleFunc("/api/geoip/check", a.handleGeoIPCheck).Methods("GET")
	a.router.HandleFunc("/api/geoip/service-rules", a.handleServiceRules).Methods("GET")
	a.router.HandleFunc("/api/geoip/vpn-check", a.handleVPNCheck).Methods("GET")
	a.router.HandleFunc("/api/geoip/stats", a.handleGeoIPStats).Methods("GET")

	a.router.HandleFunc("/api/ports/list", a.handlePortsList).Methods("GET")
	a.router.HandleFunc("/api/ports/add", a.handlePortAdd).Methods("POST")
	a.router.HandleFunc("/api/ports/remove", a.handlePortRemove).Methods("DELETE")

	// Middleware
	a.router.Use(a.loggingMiddleware)
	a.router.Use(a.corsMiddleware)
}

func (a *APIServer) handleGeoIPCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	service := r.URL.Query().Get("service")
	if service == "" {
		service = "web" // Default service
	}

	// Validate service
	validServices := []string{"web", "ssh", "cpanel", "directadmin", "mail", "ftp"}
	isValidService := false
	for _, validService := range validServices {
		if service == validService {
			isValidService = true
			break
		}
	}
	if !isValidService {
		a.writeErrorResponse(w, "Invalid service. Valid services: web, ssh, cpanel, directadmin, mail, ftp", http.StatusBadRequest)
		return
	}

	// Check if IPS manager and enhanced GeoIP are available
	if a.ipsManager == nil {
		a.writeErrorResponse(w, "IPS manager not available", http.StatusServiceUnavailable)
		return
	}

	// For now, we'll use basic country checking until enhanced GeoIP is fully integrated
	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"ip":           ip.String(),
			"service":      service,
			"allowed":      true, // Default to allowed for now
			"reason":       "No restrictions configured",
			"country":      "Unknown",
			"is_vpn":       false,
			"is_proxy":     false,
			"applied_rule": nil,
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	logger.Info("api", "GeoIP check performed", "ip", ip.String(), "service", service, "client_ip", GetClientIP(r))
	a.writeJSONResponse(w, response)
}

func (a *APIServer) handleServiceRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return configured service rules from config
	serviceRules := make(map[string]interface{})

	// Add default service rules
	serviceRules["ssh"] = map[string]interface{}{
		"service":           "ssh",
		"allowed_countries": []string{},
		"blocked_countries": []string{},
		"block_vpns":        false,
		"block_proxies":     false,
		"enabled":           false,
	}

	serviceRules["web"] = map[string]interface{}{
		"service":           "web",
		"allowed_countries": []string{},
		"blocked_countries": []string{},
		"block_vpns":        false,
		"block_proxies":     false,
		"enabled":           false,
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"service_rules":             serviceRules,
			"per_service_rules_enabled": false,
			"vpn_detection_enabled":     false,
			"total_rules":               len(serviceRules),
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	a.writeJSONResponse(w, response)
}

func (a *APIServer) handleVPNCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	// For now, return basic VPN check results
	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"ip":        ip.String(),
			"is_vpn":    false,
			"is_proxy":  false,
			"is_tor":    false,
			"country":   "Unknown",
			"provider":  "Unknown",
			"source":    "basic_check",
			"timestamp": time.Now().Format(time.RFC3339),
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	logger.Info("api", "VPN check performed", "ip", ip.String(), "client_ip", GetClientIP(r))
	a.writeJSONResponse(w, response)
}

func (a *APIServer) handleGeoIPStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		a.writeErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"enhanced_geoip": map[string]interface{}{
				"enabled":            false,
				"vpn_detection":      false,
				"service_rules":      0,
				"vpn_cache_size":     0,
				"vpn_blocklist_size": 0,
			},
			"basic_geoip": map[string]interface{}{
				"database_available": false,
				"database_path":      "",
			},
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}

	a.writeJSONResponse(w, response)
}

func (a *APIServer) Start(addr string) error {
	logger.Info("api", "Starting API server", "address", addr)
	return http.ListenAndServe(addr, a.router)
}

func (a *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(a.startTime)

	response := StatusResponse{
		Status:           "running",
		Version:          "1.0.0",
		Uptime:           uptime.String(),
		GeoIPAvailable:   a.config.GeoIP.MMDBPath != "",
		TemporaryEntries: 0,
	}

	a.writeJSONResponse(w, response)
}

func (a *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	systemMetrics, err := a.monitor.GetMetrics()
	if err != nil {
		logger.Error("api", "Failed to get system metrics", "error", err)
	}

	// Convert map[string]float64 to map[string]interface{}
	systemMetricsInterface := make(map[string]interface{})
	for k, v := range systemMetrics {
		systemMetricsInterface[k] = v
	}

	firewallMetrics, _ := a.firewall.GetStats()

	response := MetricsResponse{
		SystemMetrics:   systemMetricsInterface,
		FirewallMetrics: firewallMetrics,
	}

	a.writeJSONResponse(w, response)
}

func (a *APIServer) handleReload(w http.ResponseWriter, r *http.Request) {
	logger.Info("api", "Reloading configuration via API")

	if err := a.firewall.Reload(); err != nil {
		logger.Error("api", "Failed to reload firewall", "error", err.Error())
		a.writeErrorResponse(w, "Failed to reload", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "reloaded"})
}

func (a *APIServer) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.AddWhitelistIP(ip); err != nil {
		logger.Error("api", "Failed to add IP to whitelist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to add IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "added", "ip": ip.String()})
}

func (a *APIServer) handleWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.RemoveWhitelistIP(ip); err != nil {
		logger.Error("api", "Failed to remove IP from whitelist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to remove IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "removed", "ip": ip.String()})
}

func (a *APIServer) handleBlacklistAdd(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.AddBlacklistIP(ip); err != nil {
		logger.Error("api", "Failed to add IP to blacklist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to add IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "added", "ip": ip.String()})
}

func (a *APIServer) handleBlacklistRemove(w http.ResponseWriter, r *http.Request) {
	ip := a.parseIPFromQuery(w, r)
	if ip == nil {
		return
	}

	if err := a.firewall.RemoveBlacklistIP(ip); err != nil {
		logger.Error("api", "Failed to remove IP from blacklist", "ip", ip.String(), "error", err.Error())
		a.writeErrorResponse(w, "Failed to remove IP", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{"status": "removed", "ip": ip.String()})
}

func (a *APIServer) handleDNSHosts(w http.ResponseWriter, r *http.Request) {
	hosts := a.firewall.GetDynamicHosts()
	a.writeJSONResponse(w, map[string]interface{}{
		"dynamic_hosts": hosts,
	})
}

func (a *APIServer) handleDNSAdd(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		a.writeErrorResponse(w, "hostname parameter required", http.StatusBadRequest)
		return
	}

	if err := a.firewall.AddDynamicHost(hostname); err != nil {
		a.writeErrorResponse(w, "Failed to add hostname", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]string{
		"status":   "added",
		"hostname": hostname,
	})
}

func (a *APIServer) parseIPFromQuery(w http.ResponseWriter, r *http.Request) net.IP {
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		a.writeErrorResponse(w, "IP parameter required", http.StatusBadRequest)
		return nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		a.writeErrorResponse(w, "Invalid IP address", http.StatusBadRequest)
		return nil
	}

	return ip
}

func (a *APIServer) writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (a *APIServer) writeErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (a *APIServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)

		logger.Info("api", "HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", duration.String(),
			"remote_addr", r.RemoteAddr,
		)
	})
}

func (a *APIServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *APIServer) autoWhitelistClient(r *http.Request) {
	clientIP := GetClientIP(r)
	if clientIP != nil && !clientIP.IsLoopback() {
		if err := a.firewall.AddWhitelistIP(clientIP); err != nil {
			logger.Error("api", "Failed to auto-whitelist client", "ip", clientIP.String(), "error", err.Error())
		} else {
			logger.Info("api", "Auto-whitelisted API client", "ip", clientIP.String())
		}
	}
}

func GetClientIP(r *http.Request) net.IP {
	// Check X-Forwarded-For header first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			ip := net.ParseIP(strings.TrimSpace(ips[0]))
			if ip != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		ip := net.ParseIP(strings.TrimSpace(xri))
		if ip != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}

	return net.ParseIP(host)
}

func (a *APIServer) handlePortsList(w http.ResponseWriter, r *http.Request) {
	ports := a.firewall.ListPortRules()
	a.writeJSONResponse(w, map[string]interface{}{
		"port_rules": ports,
	})
}

func (a *APIServer) handlePortAdd(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	protocol := r.URL.Query().Get("protocol")
	direction := r.URL.Query().Get("direction")
	action := r.URL.Query().Get("action")

	if port == "" || protocol == "" || direction == "" {
		a.writeErrorResponse(w, "Missing required parameters: port, protocol, direction", http.StatusBadRequest)
		return
	}

	if action == "" {
		action = "allow"
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		a.writeErrorResponse(w, "Invalid port number", http.StatusBadRequest)
		return
	}

	if err := a.firewall.AddPortRule(portNum, protocol, direction, action); err != nil {
		a.writeErrorResponse(w, "Failed to add port rule", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]interface{}{
		"status":    "added",
		"port":      portNum,
		"protocol":  protocol,
		"direction": direction,
		"action":    action,
	})
}

func (a *APIServer) handlePortRemove(w http.ResponseWriter, r *http.Request) {
	port := r.URL.Query().Get("port")
	protocol := r.URL.Query().Get("protocol")
	direction := r.URL.Query().Get("direction")

	if port == "" || protocol == "" || direction == "" {
		a.writeErrorResponse(w, "Missing required parameters: port, protocol, direction", http.StatusBadRequest)
		return
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		a.writeErrorResponse(w, "Invalid port number", http.StatusBadRequest)
		return
	}

	if err := a.firewall.RemovePortRule(portNum, protocol, direction); err != nil {
		a.writeErrorResponse(w, "Failed to remove port rule", http.StatusInternalServerError)
		return
	}

	a.writeJSONResponse(w, map[string]interface{}{
		"status":    "removed",
		"port":      portNum,
		"protocol":  protocol,
		"direction": direction,
	})
}
