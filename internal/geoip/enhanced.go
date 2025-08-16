// internal/geoip/enhanced.go
package geoip

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/logger"
)

type EnhancedGeoIPManager struct {
	basicGeoIP   *GeoIPManager
	config       *config.GeoIPConfig
	vpnCache     map[string]*VPNResult
	vpnBlocklist map[string]bool
	mu           sync.RWMutex
	stopCh       chan struct{}
}

type VPNResult struct {
	IP        string
	IsVPN     bool
	IsProxy   bool
	IsTor     bool
	Country   string
	Provider  string
	Timestamp time.Time
	Source    string
}

type ServiceDecision struct {
	Allow       bool
	Reason      string
	Country     string
	IsVPN       bool
	IsProxy     bool
	Service     string
	AppliedRule *config.ServiceRule
}

// IPQualityScore API response structure
type IPQSResponse struct {
	Success     bool   `json:"success"`
	FraudScore  int    `json:"fraud_score"`
	CountryCode string `json:"country_code"`
	ISP         string `json:"ISP"`
	ASN         int    `json:"ASN"`
	VPN         bool   `json:"vpn"`
	Tor         bool   `json:"tor"`
	Proxy       bool   `json:"proxy"`
	Mobile      bool   `json:"mobile"`
	Message     string `json:"message"`
}

func NewEnhancedGeoIPManager(basicGeoIP *GeoIPManager, cfg *config.GeoIPConfig) *EnhancedGeoIPManager {
	egm := &EnhancedGeoIPManager{
		basicGeoIP:   basicGeoIP,
		config:       cfg,
		vpnCache:     make(map[string]*VPNResult),
		vpnBlocklist: make(map[string]bool),
		stopCh:       make(chan struct{}),
	}

	egm.setDefaults()
	return egm
}

func (e *EnhancedGeoIPManager) setDefaults() {
	if e.config.CacheExpiration == 0 {
		e.config.CacheExpiration = 24 * time.Hour
	}

	if e.config.VPNDetectionAPI == "" {
		e.config.VPNDetectionAPI = "ipqualityscore" // Default to IPQS
	}

	// Set default VPN blocklists if none configured
	if len(e.config.VPNBlocklists) == 0 {
		e.config.VPNBlocklists = []string{
			"https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt",
			"https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.txt",
		}
	}

	// Initialize default service rules if not configured
	if e.config.ServiceRules == nil {
		e.config.ServiceRules = make(map[string]*config.ServiceRule)
	}

	// Add default SSH rule if none exists
	if _, exists := e.config.ServiceRules["ssh"]; !exists {
		e.config.ServiceRules["ssh"] = &config.ServiceRule{
			Service:      "ssh",
			BlockVPNs:    true,
			BlockProxies: true,
			Enabled:      true,
		}
	}
}

func (e *EnhancedGeoIPManager) Initialize() error {
	if !e.config.EnablePerServiceRules && !e.config.EnableVPNDetection {
		return nil
	}

	logger.Info("geoip", "Initializing enhanced GeoIP manager")

	// Load VPN blocklists
	if e.config.EnableVPNDetection {
		go e.loadVPNBlocklists()
		go e.startCacheCleanup()
	}

	return nil
}

func (e *EnhancedGeoIPManager) loadVPNBlocklists() {
	logger.Info("geoip", "Loading VPN blocklists")

	for _, url := range e.config.VPNBlocklists {
		e.loadVPNBlocklist(url)
	}

	logger.Info("geoip", "VPN blocklists loaded", "count", len(e.vpnBlocklist))
}

func (e *EnhancedGeoIPManager) loadVPNBlocklist(url string) {
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		logger.Error("geoip", "Failed to fetch VPN blocklist", "url", url, "error", err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		logger.Error("geoip", "VPN blocklist returned non-200", "url", url, "status", resp.StatusCode)
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	count := 0

	e.mu.Lock()
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			// Handle both single IPs and CIDR ranges
			if ip := net.ParseIP(line); ip != nil {
				e.vpnBlocklist[line] = true
				count++
			} else if _, _, err := net.ParseCIDR(line); err == nil {
				e.vpnBlocklist[line] = true
				count++
			}
		}
	}
	e.mu.Unlock()

	logger.Info("geoip", "Loaded VPN blocklist", "url", url, "entries", count)
}

func (e *EnhancedGeoIPManager) CheckServiceAccess(ip net.IP, service string) *ServiceDecision {
	decision := &ServiceDecision{
		Allow:   true,
		Service: service,
		Country: e.basicGeoIP.GetCountry(ip),
	}

	// Check if service has specific rules
	rule, hasRule := e.config.ServiceRules[service]
	if !hasRule || !rule.Enabled {
		// No specific rule, fall back to basic GeoIP blocking
		if e.basicGeoIP.IsBlocked(ip) {
			decision.Allow = false
			decision.Reason = "Country blocked by basic GeoIP rules"
		}
		return decision
	}

	decision.AppliedRule = rule

	// Check VPN/Proxy if enabled for this service
	if e.config.EnableVPNDetection && (rule.BlockVPNs || rule.BlockProxies) {
		vpnResult := e.checkVPN(ip)
		decision.IsVPN = vpnResult.IsVPN
		decision.IsProxy = vpnResult.IsProxy

		if rule.BlockVPNs && vpnResult.IsVPN {
			decision.Allow = false
			decision.Reason = fmt.Sprintf("VPN detected (%s)", vpnResult.Provider)
			return decision
		}

		if rule.BlockProxies && vpnResult.IsProxy {
			decision.Allow = false
			decision.Reason = "Proxy detected"
			return decision
		}
	}

	// Check country rules
	country := decision.Country

	// If allowed countries specified, must be in the list
	if len(rule.AllowedCountries) > 0 {
		allowed := false
		for _, allowedCountry := range rule.AllowedCountries {
			if country == allowedCountry {
				allowed = true
				break
			}
		}
		if !allowed {
			decision.Allow = false
			decision.Reason = fmt.Sprintf("Country %s not in allowed list for %s", country, service)
			return decision
		}
	}

	// Check blocked countries
	for _, blockedCountry := range rule.BlockedCountries {
		if country == blockedCountry {
			decision.Allow = false
			decision.Reason = fmt.Sprintf("Country %s blocked for %s", country, service)
			return decision
		}
	}

	return decision
}

func (e *EnhancedGeoIPManager) checkVPN(ip net.IP) *VPNResult {
	ipStr := ip.String()

	// Check cache first
	e.mu.RLock()
	if cached, exists := e.vpnCache[ipStr]; exists {
		if time.Since(cached.Timestamp) < e.config.CacheExpiration {
			e.mu.RUnlock()
			return cached
		}
	}
	e.mu.RUnlock()

	// Check static blocklist first (faster)
	result := e.checkVPNBlocklist(ip)
	if result.IsVPN || result.IsProxy {
		e.cacheVPNResult(ipStr, result)
		return result
	}

	// Check API if configured
	if e.config.VPNAPIKey != "" {
		if apiResult := e.checkVPNAPI(ip); apiResult != nil {
			e.cacheVPNResult(ipStr, apiResult)
			return apiResult
		}
	}

	// Cache negative result
	result.Timestamp = time.Now()
	e.cacheVPNResult(ipStr, result)
	return result
}

func (e *EnhancedGeoIPManager) checkVPNBlocklist(ip net.IP) *VPNResult {
	ipStr := ip.String()

	e.mu.RLock()
	defer e.mu.RUnlock()

	result := &VPNResult{
		IP:        ipStr,
		Timestamp: time.Now(),
		Source:    "blocklist",
	}

	// Check exact IP match
	if e.vpnBlocklist[ipStr] {
		result.IsVPN = true
		result.Provider = "Known VPN/Proxy"
		return result
	}

	// Check CIDR ranges (simplified - you might want to optimize this)
	for cidr := range e.vpnBlocklist {
		if strings.Contains(cidr, "/") {
			if _, network, err := net.ParseCIDR(cidr); err == nil {
				if network.Contains(ip) {
					result.IsVPN = true
					result.Provider = "VPN Range"
					return result
				}
			}
		}
	}

	return result
}

func (e *EnhancedGeoIPManager) checkVPNAPI(ip net.IP) *VPNResult {
	switch e.config.VPNDetectionAPI {
	case "ipqualityscore":
		return e.checkIPQualityScore(ip)
	default:
		logger.Warn("geoip", "Unknown VPN detection API", "api", e.config.VPNDetectionAPI)
		return nil
	}
}

func (e *EnhancedGeoIPManager) checkIPQualityScore(ip net.IP) *VPNResult {
	url := fmt.Sprintf("https://ipqualityscore.com/api/json/ip/%s/%s",
		e.config.VPNAPIKey, ip.String())

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		logger.Error("geoip", "IPQS API request failed", "error", err.Error())
		return nil
	}
	defer resp.Body.Close()

	var ipqsResp IPQSResponse
	if err := json.NewDecoder(resp.Body).Decode(&ipqsResp); err != nil {
		logger.Error("geoip", "Failed to decode IPQS response", "error", err.Error())
		return nil
	}

	if !ipqsResp.Success {
		logger.Error("geoip", "IPQS API returned error", "message", ipqsResp.Message)
		return nil
	}

	return &VPNResult{
		IP:        ip.String(),
		IsVPN:     ipqsResp.VPN,
		IsProxy:   ipqsResp.Proxy,
		IsTor:     ipqsResp.Tor,
		Country:   ipqsResp.CountryCode,
		Provider:  ipqsResp.ISP,
		Timestamp: time.Now(),
		Source:    "ipqualityscore",
	}
}

func (e *EnhancedGeoIPManager) cacheVPNResult(ip string, result *VPNResult) {
	if !e.config.CacheVPNResults {
		return
	}

	e.mu.Lock()
	e.vpnCache[ip] = result
	e.mu.Unlock()
}

func (e *EnhancedGeoIPManager) startCacheCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.cleanupCache()
		case <-e.stopCh:
			return
		}
	}
}

func (e *EnhancedGeoIPManager) cleanupCache() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for ip, result := range e.vpnCache {
		if now.Sub(result.Timestamp) > e.config.CacheExpiration {
			delete(e.vpnCache, ip)
			cleaned++
		}
	}

	if cleaned > 0 {
		logger.Info("geoip", "Cleaned up VPN cache", "entries", cleaned)
	}
}

func (e *EnhancedGeoIPManager) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"enhanced_enabled":   e.config.EnablePerServiceRules,
		"vpn_detection":      e.config.EnableVPNDetection,
		"service_rules":      len(e.config.ServiceRules),
		"vpn_cache_size":     len(e.vpnCache),
		"vpn_blocklist_size": len(e.vpnBlocklist),
		"cache_expiration":   e.config.CacheExpiration.String(),
	}
}

func (e *EnhancedGeoIPManager) Stop() {
	close(e.stopCh)
}
