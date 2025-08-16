// internal/ips/ips.go
package ips

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"qfw/internal/config"
	"qfw/internal/firewall"
	"qfw/internal/geoip"
	"qfw/internal/logger"
	"qfw/internal/notify"
)

type IPSManager struct {
	config            *config.IPSConfig
	firewall          *firewall.NFTManager
	notifier          *notify.Notifier
	geoipManager      *geoip.EnhancedGeoIPManager
	blockedIPs        map[string]*BlockEntry
	tempWhitelist     map[string]*WhitelistEntry
	attackCounters    map[string]*AttackCounter
	mu                sync.RWMutex
	stopCh            chan struct{}
	logPatterns       map[string]*DetectionRule
	portScanDetector  *PortScanDetector
	fileSystemMonitor *FileSystemMonitor
	processMonitor    *ProcessMonitor
	blocklistManager  *ExternalBlocklistManager
}

type BlockEntry struct {
	IP         net.IP
	Reason     string
	Service    string
	BlockTime  time.Time
	ExpiryTime *time.Time
	Permanent  bool
	HitCount   int
	LastSeen   time.Time
}

type WhitelistEntry struct {
	IP         net.IP
	ExpiryTime *time.Time
	Permanent  bool
	Reason     string
	AddedTime  time.Time
}

type AttackCounter struct {
	IP         net.IP
	Service    string
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	LogEntries []string
}

type DetectionRule struct {
	Name       string
	Service    string
	Pattern    *regexp.Regexp
	Threshold  int
	TimeWindow time.Duration
	LogFiles   []string
}

func NewIPSManager(cfg *config.IPSConfig, fw *firewall.NFTManager, notifier *notify.Notifier, geoipMgr *geoip.EnhancedGeoIPManager) *IPSManager {
	ips := &IPSManager{
		config:         cfg,
		firewall:       fw,
		notifier:       notifier,
		geoipManager:   geoipMgr,
		blockedIPs:     make(map[string]*BlockEntry),
		tempWhitelist:  make(map[string]*WhitelistEntry),
		attackCounters: make(map[string]*AttackCounter),
		stopCh:         make(chan struct{}),
		logPatterns:    make(map[string]*DetectionRule),
	}

	ips.portScanDetector = NewPortScanDetector(cfg, ips)
	ips.fileSystemMonitor = NewFileSystemMonitor(cfg, ips)
	ips.processMonitor = NewProcessMonitor(cfg, ips)
	ips.blocklistManager = NewExternalBlocklistManager(cfg, ips)

	ips.initializePatterns()
	return ips
}

func (i *IPSManager) initializePatterns() {
	// Set default log files if not configured
	i.setDefaultLogFiles()

	// cPanel login failures
	i.logPatterns["cpanel_failed"] = &DetectionRule{
		Name:       "cPanel Failed Login",
		Service:    "cpanel",
		Pattern:    regexp.MustCompile(`\[info\] .* FAILED LOGIN .* from (\d+\.\d+\.\d+\.\d+)`),
		Threshold:  i.config.CPanelFailedLogins,
		TimeWindow: i.config.CPanelTimeWindow,
		LogFiles:   i.config.CPanelLogFiles,
	}

	// DirectAdmin login failures
	i.logPatterns["directadmin_failed"] = &DetectionRule{
		Name:       "DirectAdmin Failed Login",
		Service:    "directadmin",
		Pattern:    regexp.MustCompile(`SECURITY_VIOLATION\|([0-9.]+)\|.*\|LOGIN_FAILED`),
		Threshold:  i.config.DirectAdminFailedLogins,
		TimeWindow: i.config.DirectAdminTimeWindow,
		LogFiles:   i.config.DirectAdminLogFiles,
	}

	// WordPress login failures
	i.logPatterns["wordpress_failed"] = &DetectionRule{
		Name:       "WordPress Failed Login",
		Service:    "wordpress",
		Pattern:    regexp.MustCompile(`authentication failure.*rhost=(\d+\.\d+\.\d+\.\d+)`),
		Threshold:  i.config.WordPressFailedLogins,
		TimeWindow: i.config.WordPressTimeWindow,
		LogFiles:   i.config.AuthLogFiles,
	}

	// Apache scanning
	i.logPatterns["apache_scan"] = &DetectionRule{
		Name:       "Apache 404 Scanning",
		Service:    "web",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+) .* "GET .* HTTP/1\.[01]" 404`),
		Threshold:  10,
		TimeWindow: 2 * time.Minute,
		LogFiles:   i.config.ApacheLogFiles,
	}

	// Nginx scanning
	i.logPatterns["nginx_scan"] = &DetectionRule{
		Name:       "Nginx 404 Scanning",
		Service:    "web",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+) .* "GET .* HTTP/1\.[01]" 404`),
		Threshold:  10,
		TimeWindow: 2 * time.Minute,
		LogFiles:   i.config.NginxLogFiles,
	}

	// FTP brute force
	i.logPatterns["ftp_failed"] = &DetectionRule{
		Name:       "FTP Failed Login",
		Service:    "ftp",
		Pattern:    regexp.MustCompile(`FAIL LOGIN.*Client "(\d+\.\d+\.\d+\.\d+)"`),
		Threshold:  3,
		TimeWindow: 5 * time.Minute,
		LogFiles:   i.config.FTPLogFiles,
	}

	// SMTP Authentication failures
	i.logPatterns["smtp_auth_failed"] = &DetectionRule{
		Name:       "SMTP Auth Failed",
		Service:    "smtp",
		Pattern:    regexp.MustCompile(`warning: [^[]*\[(\d+\.\d+\.\d+\.\d+)\]: SASL.*authentication failed`),
		Threshold:  5,
		TimeWindow: 15 * time.Minute,
		LogFiles:   i.config.MailLogFiles,
	}

	// SQL Injection (Apache)
	i.logPatterns["apache_sql_injection"] = &DetectionRule{
		Name:       "SQL Injection Attempt",
		Service:    "web",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"[^"]*(?:union|select|insert|delete|update|drop|create|alter).*(?:from|where|join).*"`),
		Threshold:  1,
		TimeWindow: 1 * time.Minute,
		LogFiles:   i.config.ApacheLogFiles,
	}

	// SQL Injection (Nginx)
	i.logPatterns["nginx_sql_injection"] = &DetectionRule{
		Name:       "SQL Injection Attempt",
		Service:    "web",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"[^"]*(?:union|select|insert|delete|update|drop|create|alter).*(?:from|where|join).*"`),
		Threshold:  1,
		TimeWindow: 1 * time.Minute,
		LogFiles:   i.config.NginxLogFiles,
	}

	// Shell Upload (Apache)
	i.logPatterns["apache_shell_upload"] = &DetectionRule{
		Name:       "Shell Upload Attempt",
		Service:    "web",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"POST.*\.(?:php|asp|jsp|sh).*"`),
		Threshold:  1,
		TimeWindow: 1 * time.Minute,
		LogFiles:   i.config.ApacheLogFiles,
	}

	// Shell Upload (Nginx)
	i.logPatterns["nginx_shell_upload"] = &DetectionRule{
		Name:       "Shell Upload Attempt",
		Service:    "web",
		Pattern:    regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"POST.*\.(?:php|asp|jsp|sh).*"`),
		Threshold:  1,
		TimeWindow: 1 * time.Minute,
		LogFiles:   i.config.NginxLogFiles,
	}
}

func (i *IPSManager) Start() error {
	if !i.config.EnableIPS {
		return nil
	}

	logger.Info("ips", "Starting IPS manager")

	// Auto-whitelist current SSH session
	if i.config.AutoWhitelistSSH {
		i.autoWhitelistSSHSessions()
	}

	// Start Phase 1 components
	go i.startLogMonitoring()
	go i.startCleanupRoutine()

	// Start Phase 2 components
	if err := i.portScanDetector.Start(); err != nil {
		logger.Error("ips", "Failed to start port scan detector", "error", err.Error())
	}

	if err := i.fileSystemMonitor.Start(); err != nil {
		logger.Error("ips", "Failed to start filesystem monitor", "error", err.Error())
	}

	if err := i.processMonitor.Start(); err != nil {
		logger.Error("ips", "Failed to start process monitor", "error", err.Error())
	}

	if err := i.blocklistManager.Start(); err != nil {
		logger.Error("ips", "Failed to start blocklist manager", "error", err.Error())
	}

	return nil
}

func (i *IPSManager) setDefaultLogFiles() {
	if len(i.config.CPanelLogFiles) == 0 {
		i.config.CPanelLogFiles = []string{"/usr/local/cpanel/logs/login_log", "/usr/local/cpanel/logs/access_log"}
	}

	if len(i.config.DirectAdminLogFiles) == 0 {
		i.config.DirectAdminLogFiles = []string{"/var/log/directadmin/security.log", "/var/log/directadmin/login.log"}
	}

	if len(i.config.ApacheLogFiles) == 0 {
		i.config.ApacheLogFiles = []string{"/var/log/apache2/access.log", "/var/log/httpd/access_log"}
	}

	if len(i.config.NginxLogFiles) == 0 {
		i.config.NginxLogFiles = []string{"/var/log/nginx/access.log"}
	}

	if len(i.config.MailLogFiles) == 0 {
		i.config.MailLogFiles = []string{"/var/log/mail.log", "/var/log/maillog"}
	}

	if len(i.config.FTPLogFiles) == 0 {
		i.config.FTPLogFiles = []string{"/var/log/vsftpd.log", "/var/log/proftpd/proftpd.log"}
	}

	if len(i.config.AuthLogFiles) == 0 {
		i.config.AuthLogFiles = []string{"/var/log/auth.log", "/var/log/secure"}
	}
}

func (i *IPSManager) autoWhitelistSSHSessions() {
	sshClient := os.Getenv("SSH_CLIENT")
	if sshClient != "" {
		parts := strings.Fields(sshClient)
		if len(parts) > 0 {
			ip := net.ParseIP(parts[0])
			if ip != nil && !ip.IsLoopback() {
				expiryTime := time.Now().Add(i.config.SSHWhitelistDuration)
				i.addTempWhitelist(ip, &expiryTime, "Auto SSH session")
				logger.Info("ips", "Auto-whitelisted SSH session", "ip", ip.String(), "expires", expiryTime)
			}
		}
	}
}

func (i *IPSManager) addTempWhitelist(ip net.IP, expiryTime *time.Time, reason string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	i.tempWhitelist[key] = &WhitelistEntry{
		IP:         ip,
		ExpiryTime: expiryTime,
		Permanent:  expiryTime == nil,
		Reason:     reason,
		AddedTime:  time.Now(),
	}

	// Add to firewall whitelist
	i.firewall.AddWhitelistIP(ip)
}

func (i *IPSManager) startLogMonitoring() {
	ticker := time.NewTicker(i.config.LogCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.processLogs()
		case <-i.stopCh:
			return
		}
	}
}

func (i *IPSManager) processLogs() {
	for _, rule := range i.logPatterns {
		for _, logFile := range rule.LogFiles {
			i.processLogFile(rule, logFile)
		}
	}
}

func (i *IPSManager) processLogFile(rule *DetectionRule, logFile string) {
	file, err := os.Open(logFile)
	if err != nil {
		// Log file doesn't exist, skip silently
		return
	}
	defer file.Close()

	// Read last N lines (simple implementation - can be optimized)
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Process recent entries (last 100 lines)
	start := len(lines) - 100
	if start < 0 {
		start = 0
	}

	for _, line := range lines[start:] {
		i.processLogLine(line, rule)
	}
}

func (i *IPSManager) processLogLine(line string, rule *DetectionRule) {
	matches := rule.Pattern.FindStringSubmatch(line)
	if len(matches) < 2 {
		return
	}

	ipStr := matches[1]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	// Check if IP is whitelisted
	if i.isWhitelisted(ip) {
		return
	}

	// Enhanced GeoIP check per service
	if i.geoipManager != nil {
		decision := i.geoipManager.CheckServiceAccess(ip, rule.Service)
		if !decision.Allow {
			logger.Info("ips", "IP blocked by enhanced GeoIP",
				"ip", ip.String(),
				"service", rule.Service,
				"reason", decision.Reason,
				"country", decision.Country,
				"vpn", decision.IsVPN,
				"proxy", decision.IsProxy)

			// Block immediately for GeoIP/VPN violations
			i.blockIP(ip, decision.Reason, rule.Service, false)
			return
		}
	}

	// Track attack
	i.trackAttack(ip, rule.Service, line)

	// Check if threshold exceeded
	if i.shouldBlock(ip, rule) {
		i.blockIP(ip, rule.Name, rule.Service, false)
	}
}

func (i *IPSManager) isWhitelisted(ip net.IP) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	key := ip.String()
	entry, exists := i.tempWhitelist[key]
	if !exists {
		return false
	}

	// Check if temporary whitelist expired
	if entry.ExpiryTime != nil && time.Now().After(*entry.ExpiryTime) {
		delete(i.tempWhitelist, key)
		i.firewall.RemoveWhitelistIP(ip)
		return false
	}

	return true
}

func (i *IPSManager) trackAttack(ip net.IP, service, logEntry string) {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := fmt.Sprintf("%s:%s", ip.String(), service)
	counter, exists := i.attackCounters[key]

	if !exists {
		counter = &AttackCounter{
			IP:         ip,
			Service:    service,
			Count:      0,
			FirstSeen:  time.Now(),
			LogEntries: []string{},
		}
		i.attackCounters[key] = counter
	}

	counter.Count++
	counter.LastSeen = time.Now()
	counter.LogEntries = append(counter.LogEntries, logEntry)

	// Keep only last 10 log entries
	if len(counter.LogEntries) > 10 {
		counter.LogEntries = counter.LogEntries[1:]
	}
}

func (i *IPSManager) shouldBlock(ip net.IP, rule *DetectionRule) bool {
	i.mu.RLock()
	defer i.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", ip.String(), rule.Service)
	counter, exists := i.attackCounters[key]
	if !exists {
		return false
	}

	// Check if within time window and exceeded threshold
	if time.Since(counter.FirstSeen) <= rule.TimeWindow && counter.Count >= rule.Threshold {
		return true
	}

	return false
}

func (i *IPSManager) blockIP(ip net.IP, reason, service string, permanent bool) {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()

	// Check if already blocked
	if _, exists := i.blockedIPs[key]; exists {
		return
	}

	var expiryTime *time.Time
	if !permanent {
		expiry := time.Now().Add(i.config.TempBlockDuration)
		expiryTime = &expiry
	}

	entry := &BlockEntry{
		IP:         ip,
		Reason:     reason,
		Service:    service,
		BlockTime:  time.Now(),
		ExpiryTime: expiryTime,
		Permanent:  permanent,
		HitCount:   1,
		LastSeen:   time.Now(),
	}

	i.blockedIPs[key] = entry

	// Add to firewall
	i.firewall.AddBlacklistIP(ip)

	// Send notification
	if i.config.EnableBlockNotifications {
		i.sendBlockNotification(entry)
	}

	logger.Info("ips", "Blocked IP", "ip", ip.String(), "reason", reason, "service", service, "permanent", permanent)
}

func (i *IPSManager) sendBlockNotification(entry *BlockEntry) {
	// Get attack details
	key := fmt.Sprintf("%s:%s", entry.IP.String(), entry.Service)
	counter := i.attackCounters[key]

	data := map[string]interface{}{
		"ip":         entry.IP.String(),
		"reason":     entry.Reason,
		"service":    entry.Service,
		"permanent":  entry.Permanent,
		"block_time": entry.BlockTime,
	}

	if counter != nil {
		data["attack_count"] = counter.Count
		data["first_seen"] = counter.FirstSeen
		data["log_sample"] = counter.LogEntries[len(counter.LogEntries)-1]
	}

	message := fmt.Sprintf("IPS: Blocked %s for %s (%s)", entry.IP.String(), entry.Reason, entry.Service)
	i.notifier.SendAlert(message, data)
}

func (i *IPSManager) startCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			i.cleanupExpiredEntries()
		case <-i.stopCh:
			return
		}
	}
}

func (i *IPSManager) cleanupExpiredEntries() {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := time.Now()

	// Cleanup expired blocks
	for key, entry := range i.blockedIPs {
		if entry.ExpiryTime != nil && now.After(*entry.ExpiryTime) {
			i.firewall.RemoveBlacklistIP(entry.IP)
			delete(i.blockedIPs, key)
			logger.Info("ips", "Unblocked expired IP", "ip", entry.IP.String())
		}
	}

	// Cleanup expired whitelists
	for key, entry := range i.tempWhitelist {
		if entry.ExpiryTime != nil && now.After(*entry.ExpiryTime) {
			i.firewall.RemoveWhitelistIP(entry.IP)
			delete(i.tempWhitelist, key)
			logger.Info("ips", "Removed expired whitelist", "ip", entry.IP.String())
		}
	}

	// Cleanup old attack counters
	for key, counter := range i.attackCounters {
		if now.Sub(counter.LastSeen) > 1*time.Hour {
			delete(i.attackCounters, key)
		}
	}
}

func (i *IPSManager) GetBlockedIPs() map[string]*BlockEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	result := make(map[string]*BlockEntry)
	for k, v := range i.blockedIPs {
		result[k] = v
	}
	return result
}

func (i *IPSManager) Stop() {
	close(i.stopCh)

	// Stop Phase 2 components
	if i.portScanDetector != nil {
		i.portScanDetector.Stop()
	}
	if i.fileSystemMonitor != nil {
		i.fileSystemMonitor.Stop()
	}
	if i.processMonitor != nil {
		i.processMonitor.Stop()
	}
	if i.blocklistManager != nil {
		i.blocklistManager.Stop()
	}
}

func (i *IPSManager) UnblockIP(ip net.IP) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	entry, exists := i.blockedIPs[key]
	if !exists {
		return fmt.Errorf("IP not blocked")
	}

	// Remove from firewall
	if err := i.firewall.RemoveBlacklistIP(ip); err != nil {
		return err
	}

	// Remove from blocked list
	delete(i.blockedIPs, key)

	logger.Info("ips", "Manually unblocked IP", "ip", ip.String(), "reason", entry.Reason)
	return nil
}

func (i *IPSManager) RemoveWhitelist(ip net.IP) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	key := ip.String()
	_, exists := i.tempWhitelist[key]
	if !exists {
		return fmt.Errorf("IP not whitelisted")
	}

	// Remove from whitelist
	delete(i.tempWhitelist, key)

	logger.Info("ips", "Removed whitelist", "ip", ip.String())
	return nil
}

func (i *IPSManager) GetWhitelistedIPs() map[string]*WhitelistEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	result := make(map[string]*WhitelistEntry)
	for k, v := range i.tempWhitelist {
		result[k] = v
	}
	return result
}

func (i *IPSManager) AddWhitelist(ip net.IP, permanent bool, reason string) error {
	var expiryTime *time.Time
	if !permanent {
		expiry := time.Now().Add(i.config.SSHWhitelistDuration)
		expiryTime = &expiry
	}

	i.addTempWhitelist(ip, expiryTime, reason)
	logger.Info("ips", "Added whitelist", "ip", ip.String(), "permanent", permanent, "reason", reason)
	return nil
}

func (i *IPSManager) GetStats() map[string]interface{} {
	i.mu.RLock()
	defer i.mu.RUnlock()

	stats := map[string]interface{}{
		"blocked_count":     len(i.blockedIPs),
		"whitelisted_count": len(i.tempWhitelist),
		"attack_counters":   len(i.attackCounters),
		"enabled":           i.config.EnableIPS,
		"patterns_loaded":   len(i.logPatterns),
	}

	// Add Phase 2 stats
	if i.portScanDetector != nil {
		stats["port_scan_detector"] = i.portScanDetector.GetStats()
	}
	if i.fileSystemMonitor != nil {
		stats["filesystem_monitor"] = i.fileSystemMonitor.GetStats()
	}
	if i.processMonitor != nil {
		stats["process_monitor"] = i.processMonitor.GetStats()
	}
	if i.blocklistManager != nil {
		stats["blocklist_manager"] = i.blocklistManager.GetStats()
	}

	// Count by service
	serviceStats := make(map[string]int)
	for _, entry := range i.blockedIPs {
		serviceStats[entry.Service]++
	}
	stats["blocked_by_service"] = serviceStats

	return stats
}
