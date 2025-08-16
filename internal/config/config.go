// internal/config/config.go
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type IPSConfig struct {
	EnableIPS            bool          `yaml:"enable_ips"`
	LogCheckInterval     time.Duration `yaml:"log_check_interval"`
	TempBlockDuration    time.Duration `yaml:"temp_block_duration"`
	PermBlockThreshold   int           `yaml:"perm_block_threshold"`
	AutoWhitelistSSH     bool          `yaml:"auto_whitelist_ssh_sessions"`
	SSHWhitelistDuration time.Duration `yaml:"ssh_whitelist_duration"`

	// Detection rules
	CPanelFailedLogins      int           `yaml:"cpanel_failed_logins"`
	CPanelTimeWindow        time.Duration `yaml:"cpanel_time_window"`
	DirectAdminFailedLogins int           `yaml:"directadmin_failed_logins"`
	DirectAdminTimeWindow   time.Duration `yaml:"directadmin_time_window"`
	WordPressFailedLogins   int           `yaml:"wordpress_failed_logins"`
	WordPressTimeWindow     time.Duration `yaml:"wordpress_time_window"`

	// Notifications
	EnableBlockNotifications bool          `yaml:"enable_block_notifications"`
	NotifyCPanelBlocks       bool          `yaml:"notify_cpanel_blocks"`
	NotifyWebBlocks          bool          `yaml:"notify_web_blocks"`
	NotificationCooldown     time.Duration `yaml:"notification_cooldown"`

	// Log file paths
	CPanelLogFiles          []string      `yaml:"cpanel_log_files"`
	DirectAdminLogFiles     []string      `yaml:"directadmin_log_files"`
	ApacheLogFiles          []string      `yaml:"apache_log_files"`
	NginxLogFiles           []string      `yaml:"nginx_log_files"`
	MailLogFiles            []string      `yaml:"mail_log_files"`
	FTPLogFiles             []string      `yaml:"ftp_log_files"`
	AuthLogFiles            []string      `yaml:"auth_log_files"`
	EnablePortScanDetection bool          `yaml:"enable_port_scan_detection"`
	PortScanThreshold       int           `yaml:"port_scan_threshold"`
	PortScanTimeWindow      time.Duration `yaml:"port_scan_time_window"`

	EnableFileSystemMonitor bool          `yaml:"enable_filesystem_monitor"`
	CriticalFiles           []string      `yaml:"critical_files"`
	CriticalDirectories     []string      `yaml:"critical_directories"`
	FileCheckInterval       time.Duration `yaml:"file_check_interval"`

	EnableProcessMonitor bool          `yaml:"enable_process_monitor"`
	SuspiciousProcesses  []string      `yaml:"suspicious_process_patterns"`
	MaxProcessMemory     string        `yaml:"max_process_memory"`
	ProcessCheckInterval time.Duration `yaml:"process_check_interval"`

	EnableExternalBlocklists bool          `yaml:"enable_external_blocklists"`
	SpamhausEnabled          bool          `yaml:"spamhaus_enabled"`
	DShieldEnabled           bool          `yaml:"dshield_enabled"`
	BlocklistUpdateInterval  time.Duration `yaml:"blocklist_update_interval"`
}

type Config struct {
	Firewall     FirewallConfig     `yaml:"firewall"`
	Ports        PortsConfig        `yaml:"ports"`
	Security     SecurityConfig     `yaml:"security"`
	GeoIP        GeoIPConfig        `yaml:"geoip"`
	DNS          DNSConfig          `yaml:"dns"`
	RateLimit    RateLimitConfig    `yaml:"ratelimit"`
	SynFlood     SynFloodConfig     `yaml:"synflood"`
	Notification NotificationConfig `yaml:"notification"`
	Monitor      MonitorConfig      `yaml:"monitor"`
	TestMode     TestModeConfig     `yaml:"testmode"`
	IPS          IPSConfig          `yaml:"ips"`
}

type FirewallConfig struct {
	DefaultPolicy string `yaml:"default_policy"`
	EnableIPv6    bool   `yaml:"enable_ipv6"`
}

type PortsConfig struct {
	TCPIn   []int `yaml:"tcp_in"`
	TCPOut  []int `yaml:"tcp_out"`
	UDPIn   []int `yaml:"udp_in"`
	UDPOut  []int `yaml:"udp_out"`
	TCPDeny []int `yaml:"tcp_deny"`
	UDPDeny []int `yaml:"udp_deny"`
}

type SecurityConfig struct {
	EnableBogonFilter   bool          `yaml:"enable_bogon_filter"`
	EnableMartianFilter bool          `yaml:"enable_martian_filter"`
	BogonUpdateInterval time.Duration `yaml:"bogon_update_interval"`
	BogonIPv4URL        string        `yaml:"bogon_ipv4_url"`
	BogonIPv6URL        string        `yaml:"bogon_ipv6_url"`
}

type GeoIPConfig struct {
	// Existing fields...
	MMDBPath         string `yaml:"mmdb_path"`
	CountryBlockFile string `yaml:"country_block_file"`
	CountryAllowFile string `yaml:"country_allow_file"`
	MaxMindAPIKey    string `yaml:"maxmind_api_key"`
	AutoDownload     bool   `yaml:"auto_download"`

	// Enhanced GeoIP features
	EnablePerServiceRules bool                    `yaml:"enable_per_service_rules"`
	ServiceRules          map[string]*ServiceRule `yaml:"service_rules"`
	EnableVPNDetection    bool                    `yaml:"enable_vpn_detection"`
	VPNDetectionAPI       string                  `yaml:"vpn_detection_api"`
	VPNAPIKey             string                  `yaml:"vpn_api_key"`
	VPNBlocklists         []string                `yaml:"vpn_blocklists"`
	CacheVPNResults       bool                    `yaml:"cache_vpn_results"`
	CacheExpiration       time.Duration           `yaml:"cache_expiration"`
}

type ServiceRule struct {
	Service          string   `yaml:"service"`
	AllowedCountries []string `yaml:"allowed_countries"`
	BlockedCountries []string `yaml:"blocked_countries"`
	BlockVPNs        bool     `yaml:"block_vpns"`
	BlockProxies     bool     `yaml:"block_proxies"`
	Enabled          bool     `yaml:"enabled"`
}

type DNSConfig struct {
	EnableDynamicDNS bool          `yaml:"enable_dynamic_dns"`
	Hostnames        []string      `yaml:"hostnames"`
	UpdateInterval   time.Duration `yaml:"update_interval"`
}

type RateLimitConfig struct {
	EnableRateLimit    bool              `yaml:"enable_rate_limit"`
	GlobalConnLimit    int               `yaml:"global_conn_limit"`
	GlobalConnWindow   time.Duration     `yaml:"global_conn_window"`
	PortSpecificLimits map[string]string `yaml:"port_specific_limits"`
}

type SynFloodConfig struct {
	EnableProtection bool `yaml:"enable_protection"`
	SynRateLimit     int  `yaml:"syn_rate_limit"`
	SynBurst         int  `yaml:"syn_burst"`
	ConntrackMax     int  `yaml:"conntrack_max"`
}

type NotificationConfig struct {
	EnableEmail    bool     `yaml:"enable_email"`
	EmailServer    string   `yaml:"email_server"`
	EmailPort      int      `yaml:"email_port"`
	EmailUser      string   `yaml:"email_user"`
	EmailPassword  string   `yaml:"email_password"`
	EmailTo        string   `yaml:"email_to"`
	EnableWebhooks bool     `yaml:"enable_webhooks"`
	WebhookURLs    []string `yaml:"webhook_urls"`
	WebhookTimeout int      `yaml:"webhook_timeout"`
}

type MonitorConfig struct {
	EnableResourceMonitoring bool          `yaml:"enable_resource_monitoring"`
	CPUAlert                 bool          `yaml:"cpu_alert"`
	CPUThreshold             float64       `yaml:"cpu_threshold"`
	CPUDuration              time.Duration `yaml:"cpu_duration"`
	MemoryAlert              bool          `yaml:"memory_alert"`
	MemoryThreshold          float64       `yaml:"memory_threshold"`
	DiskAlert                bool          `yaml:"disk_alert"`
	DiskThreshold            float64       `yaml:"disk_threshold"`
}

type TestModeConfig struct {
	EnableTestMode  bool          `yaml:"enable_test_mode"`
	TestDuration    time.Duration `yaml:"test_duration"`
	RevertOnFailure bool          `yaml:"revert_on_failure"`
	TestConnections []string      `yaml:"test_connections"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := &Config{}
	if err := parseINI(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

func ValidateConfig(cfg *Config) error {
	if cfg.Firewall.DefaultPolicy != "accept" && cfg.Firewall.DefaultPolicy != "drop" {
		return fmt.Errorf("invalid default_policy: must be 'accept' or 'drop'")
	}

	if cfg.Monitor.CPUThreshold < 0 || cfg.Monitor.CPUThreshold > 100 {
		return fmt.Errorf("invalid cpu_threshold: must be between 0 and 100")
	}

	if cfg.Monitor.MemoryThreshold < 0 || cfg.Monitor.MemoryThreshold > 100 {
		return fmt.Errorf("invalid memory_threshold: must be between 0 and 100")
	}

	if cfg.Notification.EnableEmail {
		if cfg.Notification.EmailServer == "" || cfg.Notification.EmailTo == "" {
			return fmt.Errorf("email_server and email_to required when email notifications enabled")
		}
	}

	return nil
}

func parseINI(data []byte, cfg *Config) error {
	lines := strings.Split(string(data), "\n")
	var currentSection string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := setConfigValue(cfg, currentSection, key, value); err != nil {
			return fmt.Errorf("error setting %s.%s: %w", currentSection, key, err)
		}
	}

	return nil
}

func setConfigValue(cfg *Config, section, key, value string) error {
	switch section {
	case "firewall":
		return setFirewallConfig(&cfg.Firewall, key, value)
	case "ports":
		return setPortsConfig(&cfg.Ports, key, value)
	case "security":
		return setSecurityConfig(&cfg.Security, key, value)
	case "geoip":
		return setGeoIPConfig(&cfg.GeoIP, key, value)
	case "dns":
		return setDNSConfig(&cfg.DNS, key, value)
	case "ratelimit":
		return setRateLimitConfig(&cfg.RateLimit, key, value)
	case "synflood":
		return setSynFloodConfig(&cfg.SynFlood, key, value)
	case "notification":
		return setNotificationConfig(&cfg.Notification, key, value)
	case "monitor":
		return setMonitorConfig(&cfg.Monitor, key, value)
	case "testmode":
		return setTestModeConfig(&cfg.TestMode, key, value)
	case "ips":
		return setIPSConfig(&cfg.IPS, key, value)
	}
	return nil
}

func setFirewallConfig(cfg *FirewallConfig, key, value string) error {
	switch key {
	case "default_policy":
		cfg.DefaultPolicy = value
	case "enable_ipv6":
		cfg.EnableIPv6 = value == "true"
	}
	return nil
}

func setPortsConfig(cfg *PortsConfig, key, value string) error {
	ports := parsePorts(value)
	switch key {
	case "tcp_in":
		cfg.TCPIn = ports
	case "tcp_out":
		cfg.TCPOut = ports
	case "udp_in":
		cfg.UDPIn = ports
	case "udp_out":
		cfg.UDPOut = ports
	case "tcp_deny":
		cfg.TCPDeny = ports
	case "udp_deny":
		cfg.UDPDeny = ports
	}
	return nil
}

func parsePorts(value string) []int {
	var ports []int
	for _, p := range strings.Split(value, ",") {
		if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}

func setSecurityConfig(cfg *SecurityConfig, key, value string) error {
	switch key {
	case "enable_bogon_filter":
		cfg.EnableBogonFilter = value == "true"
	case "enable_martian_filter":
		cfg.EnableMartianFilter = value == "true"
	case "bogon_update_interval":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.BogonUpdateInterval = d
		}
	case "bogon_ipv4_url":
		cfg.BogonIPv4URL = value
	case "bogon_ipv6_url":
		cfg.BogonIPv6URL = value
	}
	return nil
}

func setGeoIPConfig(cfg *GeoIPConfig, key, value string) error {
	switch key {
	case "mmdb_path":
		cfg.MMDBPath = value
	case "country_block_file":
		cfg.CountryBlockFile = value
	case "country_allow_file":
		cfg.CountryAllowFile = value
	case "maxmind_api_key":
		cfg.MaxMindAPIKey = value
	case "auto_download":
		cfg.AutoDownload = value == "true"
	case "enable_per_service_rules":
		cfg.EnablePerServiceRules = value == "true"
	case "enable_vpn_detection":
		cfg.EnableVPNDetection = value == "true"
	case "vpn_detection_api":
		cfg.VPNDetectionAPI = value
	case "vpn_api_key":
		cfg.VPNAPIKey = value
	case "vpn_blocklists":
		cfg.VPNBlocklists = parseLogFiles(value)
	case "cache_vpn_results":
		cfg.CacheVPNResults = value == "true"
	case "cache_expiration":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.CacheExpiration = d
		}
	}
	return nil
}

func setDNSConfig(cfg *DNSConfig, key, value string) error {
	switch key {
	case "enable_dynamic_dns":
		cfg.EnableDynamicDNS = value == "true"
	case "hostnames":
		cfg.Hostnames = strings.Split(value, ",")
		for i := range cfg.Hostnames {
			cfg.Hostnames[i] = strings.TrimSpace(cfg.Hostnames[i])
		}
	case "update_interval":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.UpdateInterval = d
		} // Remove the extra } here
	}
	return nil
}

func setRateLimitConfig(cfg *RateLimitConfig, key, value string) error {
	switch key {
	case "enable_rate_limit":
		cfg.EnableRateLimit = value == "true"
	case "global_conn_limit":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.GlobalConnLimit = i
		}
	case "global_conn_window":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.GlobalConnWindow = d
		}
	}
	return nil
}

func setSynFloodConfig(cfg *SynFloodConfig, key, value string) error {
	switch key {
	case "enable_protection":
		cfg.EnableProtection = value == "true"
	case "syn_rate_limit":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.SynRateLimit = i
		}
	case "syn_burst":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.SynBurst = i
		}
	case "conntrack_max":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.ConntrackMax = i
		}
	}
	return nil
}

func setNotificationConfig(cfg *NotificationConfig, key, value string) error {
	switch key {
	case "enable_email":
		cfg.EnableEmail = value == "true"
	case "email_server":
		cfg.EmailServer = value
	case "email_port":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.EmailPort = i
		}
	case "email_user":
		cfg.EmailUser = value
	case "email_password":
		cfg.EmailPassword = value
	case "email_to":
		cfg.EmailTo = value
	case "enable_webhooks":
		cfg.EnableWebhooks = value == "true"
	case "webhook_urls":
		cfg.WebhookURLs = strings.Split(value, ",")
		for i := range cfg.WebhookURLs {
			cfg.WebhookURLs[i] = strings.TrimSpace(cfg.WebhookURLs[i])
		}
	case "webhook_timeout":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.WebhookTimeout = i
		}
	}
	return nil
}

func setMonitorConfig(cfg *MonitorConfig, key, value string) error {
	switch key {
	case "enable_resource_monitoring":
		cfg.EnableResourceMonitoring = value == "true"
	case "cpu_alert":
		cfg.CPUAlert = value == "true"
	case "cpu_threshold":
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			cfg.CPUThreshold = f
		}
	case "cpu_duration":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.CPUDuration = d
		}
	case "memory_alert":
		cfg.MemoryAlert = value == "true"
	case "memory_threshold":
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			cfg.MemoryThreshold = f
		}
	case "disk_alert":
		cfg.DiskAlert = value == "true"
	case "disk_threshold":
		if f, err := strconv.ParseFloat(value, 64); err == nil {
			cfg.DiskThreshold = f
		}
	}
	return nil
}

func setTestModeConfig(cfg *TestModeConfig, key, value string) error {
	switch key {
	case "enable_test_mode":
		cfg.EnableTestMode = value == "true"
	case "test_duration":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.TestDuration = d
		}
	case "revert_on_failure":
		cfg.RevertOnFailure = value == "true"
	case "test_connections":
		cfg.TestConnections = strings.Split(value, ",")
		for i := range cfg.TestConnections {
			cfg.TestConnections[i] = strings.TrimSpace(cfg.TestConnections[i])
		}
	}
	return nil
}

func setIPSConfig(cfg *IPSConfig, key, value string) error {
	switch key {
	case "enable_ips":
		cfg.EnableIPS = value == "true"
	case "log_check_interval":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.LogCheckInterval = d
		}
	case "temp_block_duration":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.TempBlockDuration = d
		}
	case "auto_whitelist_ssh_sessions":
		cfg.AutoWhitelistSSH = value == "true"
	case "ssh_whitelist_duration":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.SSHWhitelistDuration = d
		}
	case "cpanel_failed_logins":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.CPanelFailedLogins = i
		}
	case "cpanel_time_window":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.CPanelTimeWindow = d
		}
	case "enable_block_notifications":
		cfg.EnableBlockNotifications = value == "true"
	case "notify_cpanel_blocks":
		cfg.NotifyCPanelBlocks = value == "true"
	case "cpanel_log_files":
		cfg.CPanelLogFiles = parseLogFiles(value)
	case "directadmin_log_files":
		cfg.DirectAdminLogFiles = parseLogFiles(value)
	case "apache_log_files":
		cfg.ApacheLogFiles = parseLogFiles(value)
	case "nginx_log_files":
		cfg.NginxLogFiles = parseLogFiles(value)
	case "mail_log_files":
		cfg.MailLogFiles = parseLogFiles(value)
	case "ftp_log_files":
		cfg.FTPLogFiles = parseLogFiles(value)
	case "auth_log_files":
		cfg.AuthLogFiles = parseLogFiles(value)
	case "enable_port_scan_detection":
		cfg.EnablePortScanDetection = value == "true"
	case "port_scan_threshold":
		if i, err := strconv.Atoi(value); err == nil {
			cfg.PortScanThreshold = i
		}
	case "port_scan_time_window":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.PortScanTimeWindow = d
		}
	case "enable_filesystem_monitor":
		cfg.EnableFileSystemMonitor = value == "true"
	case "critical_files":
		cfg.CriticalFiles = parseLogFiles(value)
	case "critical_directories":
		cfg.CriticalDirectories = parseLogFiles(value)
	case "file_check_interval":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.FileCheckInterval = d
		}
	case "enable_process_monitor":
		cfg.EnableProcessMonitor = value == "true"
	case "suspicious_process_patterns":
		cfg.SuspiciousProcesses = parseLogFiles(value)
	case "max_process_memory":
		cfg.MaxProcessMemory = value
	case "process_check_interval":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.ProcessCheckInterval = d
		}
	case "enable_external_blocklists":
		cfg.EnableExternalBlocklists = value == "true"
	case "spamhaus_enabled":
		cfg.SpamhausEnabled = value == "true"
	case "dshield_enabled":
		cfg.DShieldEnabled = value == "true"
	case "blocklist_update_interval":
		if d, err := time.ParseDuration(value); err == nil {
			cfg.BlocklistUpdateInterval = d
		}
	}
	return nil
}

func parseLogFiles(value string) []string {
	var files []string
	for _, f := range strings.Split(value, ",") {
		file := strings.TrimSpace(f)
		if file != "" {
			files = append(files, file)
		}
	}
	return files
}
