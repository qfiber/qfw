// cmd/qff-cli/main.go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	Version         = "1.0.0"
	DefaultAPIBase  = "http://localhost:8080"
	ServiceName     = "qFiber Firewall"
	DefaultTimeout  = 30 * time.Second
	DefaultLogLines = 50
)

// CLI represents the command-line interface
type CLI struct {
	client *APIClient
	config *CLIConfig
}

// CLIConfig holds configuration for the CLI
type CLIConfig struct {
	APIBase string
	Timeout time.Duration
	Verbose bool
}

// APIClient handles HTTP communication with the QFF API
type APIClient struct {
	baseURL string
	client  *http.Client
}

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Handler     func(*CLI, []string) error
	Subcommands map[string]*Command
}

func main() {
	config := &CLIConfig{
		APIBase: getEnvOrDefault("QFF_API_BASE", DefaultAPIBase),
		Timeout: DefaultTimeout,
		Verbose: os.Getenv("QFF_VERBOSE") == "1",
	}

	cli := &CLI{
		client: NewAPIClient(config.APIBase, config.Timeout),
		config: config,
	}

	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func NewAPIClient(baseURL string, timeout time.Duration) *APIClient {
	return &APIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (cli *CLI) Run(args []string) error {
	if len(args) == 0 {
		return cli.showUsage()
	}

	commands := cli.getCommands()

	command := args[0]
	cmd, exists := commands[command]
	if !exists {
		return fmt.Errorf("unknown command: %s", command)
	}

	return cmd.Handler(cli, args[1:])
}

func (cli *CLI) getCommands() map[string]*Command {
	return map[string]*Command{
		"status": {
			Name:        "status",
			Description: "Show firewall status",
			Handler:     (*CLI).handleStatus,
		},
		"metrics": {
			Name:        "metrics",
			Description: "Show system metrics",
			Handler:     (*CLI).handleMetrics,
		},
		"logs": {
			Name:        "logs",
			Description: "Show recent logs",
			Handler:     (*CLI).handleLogs,
		},
		"reload": {
			Name:        "reload",
			Description: "Reload configuration",
			Handler:     (*CLI).handleReload,
		},
		"enable": {
			Name:        "enable",
			Description: "Enable and start service",
			Handler:     (*CLI).handleEnable,
		},
		"disable": {
			Name:        "disable",
			Description: "Stop and disable service",
			Handler:     (*CLI).handleDisable,
		},
		"whitelist": {
			Name:        "whitelist",
			Description: "Manage IP whitelist",
			Handler:     (*CLI).handleWhitelist,
		},
		"blacklist": {
			Name:        "blacklist",
			Description: "Manage IP blacklist",
			Handler:     (*CLI).handleBlacklist,
		},
		"ips": {
			Name:        "ips",
			Description: "IPS management commands",
			Handler:     (*CLI).handleIPS,
		},
		"ports": {
			Name:        "ports",
			Description: "Port management commands",
			Handler:     (*CLI).handlePorts,
		},
		"version": {
			Name:        "version",
			Description: "Show version information",
			Handler:     (*CLI).handleVersion,
		},
	}
}

func (cli *CLI) showUsage() error {
	fmt.Println("QFF CLI - qFibre Firewall Manager")
	fmt.Printf("Version: %s\n\n", Version)
	fmt.Println("Usage: qff-cli <command> [options]")
	fmt.Println("\nCommands:")

	commands := cli.getCommands()
	for _, cmd := range commands {
		fmt.Printf("  %-12s %s\n", cmd.Name, cmd.Description)
	}

	fmt.Println("\nEnvironment Variables:")
	fmt.Println("  QFF_API_BASE    API base URL (default: http://localhost:8080)")
	fmt.Println("  QFF_VERBOSE     Enable verbose output (set to '1')")
	fmt.Println("\nExamples:")
	fmt.Println("  qff-cli status")
	fmt.Println("  qff-cli ips status")
	fmt.Println("  qff-cli whitelist add 192.168.1.100")
	fmt.Println("  qff-cli ports add 8080 tcp in allow")

	return nil
}

// API Client methods
func (ac *APIClient) makeRequest(ctx context.Context, method, endpoint string, body io.Reader) ([]byte, error) {
	url := ac.baseURL + endpoint

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("qff-cli/%s", Version))

	resp, err := ac.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(data))
	}

	return data, nil
}

func (ac *APIClient) Get(ctx context.Context, endpoint string) ([]byte, error) {
	return ac.makeRequest(ctx, "GET", endpoint, nil)
}

func (ac *APIClient) Post(ctx context.Context, endpoint string, body io.Reader) ([]byte, error) {
	return ac.makeRequest(ctx, "POST", endpoint, body)
}

func (ac *APIClient) Delete(ctx context.Context, endpoint string) ([]byte, error) {
	return ac.makeRequest(ctx, "DELETE", endpoint, nil)
}

// Command handlers
func (cli *CLI) handleStatus(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/status")
	if err != nil {
		return err
	}

	var status StatusResponse
	if err := json.Unmarshal(data, &status); err != nil {
		return fmt.Errorf("parsing status response: %w", err)
	}

	cli.printStatus(&status)
	return nil
}

func (cli *CLI) handleMetrics(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/metrics")
	if err != nil {
		return err
	}

	var metrics MetricsResponse
	if err := json.Unmarshal(data, &metrics); err != nil {
		return fmt.Errorf("parsing metrics response: %w", err)
	}

	cli.printMetrics(&metrics)
	return nil
}

func (cli *CLI) handleLogs(args []string) error {
	lines := DefaultLogLines
	if len(args) > 0 {
		if l, err := strconv.Atoi(args[0]); err == nil && l > 0 {
			lines = l
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "journalctl", "-u", ServiceName, "-n", strconv.Itoa(lines), "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("getting logs: %w", err)
	}

	fmt.Print(string(output))
	return nil
}

func (cli *CLI) handleReload(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	_, err := cli.client.Post(ctx, "/reload", nil)
	if err != nil {
		return err
	}

	fmt.Println("Configuration reloaded successfully")
	return nil
}

func (cli *CLI) handleEnable(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "enable", "--now", ServiceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}

	fmt.Println("QFF service enabled and started")
	return nil
}

func (cli *CLI) handleDisable(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "disable", "--now", ServiceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("disabling service: %w", err)
	}

	fmt.Println("QFF service disabled and stopped")
	return nil
}

func (cli *CLI) handleVersion(args []string) error {
	fmt.Printf("qff-cli v%s\n", Version)
	return nil
}

func (cli *CLI) handleWhitelist(args []string) error {
	return cli.handleIPList("whitelist", args)
}

func (cli *CLI) handleBlacklist(args []string) error {
	return cli.handleIPList("blacklist", args)
}

func (cli *CLI) handleIPList(listType string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: qff-cli %s <add|remove|list> <ip>", listType)
	}

	action := args[0]

	switch action {
	case "list":
		return cli.listIPs(listType)
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("usage: qff-cli %s add <ip>", listType)
		}
		return cli.addIPToList(listType, args[1])
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("usage: qff-cli %s remove <ip>", listType)
		}
		return cli.removeIPFromList(listType, args[1])
	default:
		return fmt.Errorf("invalid action: %s", action)
	}
}

func (cli *CLI) addIPToList(listType, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/%s?ip=%s", listType, url.QueryEscape(ip))
	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added %s to %s\n", ip, listType)
	return nil
}

func (cli *CLI) removeIPFromList(listType, ip string) error {
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/%s?ip=%s", listType, url.QueryEscape(ip))
	_, err := cli.client.Delete(ctx, endpoint)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed %s from %s\n", ip, listType)
	return nil
}

func (cli *CLI) listIPs(listType string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/%s", listType)
	data, err := cli.client.Get(ctx, endpoint)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	cli.printIPList(listType, result)
	return nil
}

// IPS command handlers
func (cli *CLI) handleIPS(args []string) error {
	if len(args) == 0 {
		return cli.showIPSUsage()
	}

	ipsCommands := map[string]func([]string) error{
		"status":           cli.handleIPSStatus,
		"blocked":          cli.handleIPSBlocked,
		"whitelist":        cli.handleIPSWhitelist,
		"unblock":          cli.handleIPSUnblock,
		"whitelist-add":    cli.handleIPSWhitelistAdd,
		"whitelist-remove": cli.handleIPSWhitelistRemove,
		"geoip-check":      cli.handleGeoIPCheck,
		"vpn-check":        cli.handleVPNCheck,
		"service-rules":    cli.handleServiceRules,
	}

	subcommand := args[0]
	handler, exists := ipsCommands[subcommand]
	if !exists {
		return fmt.Errorf("unknown IPS command: %s", subcommand)
	}

	return handler(args[1:])
}

func (cli *CLI) showIPSUsage() error {
	fmt.Println("IPS Commands:")
	fmt.Println("  ips status                          Show IPS status and statistics")
	fmt.Println("  ips blocked                         List all blocked IPs")
	fmt.Println("  ips whitelist                       List all whitelisted IPs")
	fmt.Println("  ips unblock <ip>                    Unblock an IP address")
	fmt.Println("  ips whitelist-add <ip> [reason]     Add IP to whitelist permanently")
	fmt.Println("  ips whitelist-remove <ip>           Remove IP from whitelist")
	fmt.Println("  ips geoip-check <ip> [service]      Check GeoIP status for IP and service")
	fmt.Println("  ips vpn-check <ip>                  Check if IP is VPN/Proxy")
	fmt.Println("  ips service-rules                   Show configured service rules")
	return nil
}

func (cli *CLI) handleIPSStatus(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ips/stats")
	if err != nil {
		return err
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(data, &stats); err != nil {
		return fmt.Errorf("parsing stats response: %w", err)
	}

	fmt.Println("IPS Status:")
	cli.printKeyValue(stats, "  ")
	return nil
}

func (cli *CLI) handleIPSBlocked(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ips/blocked")
	if err != nil {
		return err
	}

	var result BlockedIPsResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing blocked IPs response: %w", err)
	}

	cli.printBlockedIPs(&result)
	return nil
}

func (cli *CLI) handleIPSWhitelist(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ips/whitelist")
	if err != nil {
		return err
	}

	var result WhitelistResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing whitelist response: %w", err)
	}

	cli.printWhitelist(&result)
	return nil
}

func (cli *CLI) handleIPSUnblock(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips unblock <ip>")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ips/unblock?ip=%s", url.QueryEscape(ip))
	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully unblocked IP: %s\n", ip)
	return nil
}

func (cli *CLI) handleIPSWhitelistAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips whitelist-add <ip> [reason]")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	reason := "Manual CLI whitelist"
	if len(args) > 1 {
		reason = strings.Join(args[1:], " ")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ips/whitelist/add?ip=%s&permanent=true&reason=%s",
		url.QueryEscape(ip), url.QueryEscape(reason))

	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully whitelisted IP: %s\n", ip)
	return nil
}

func (cli *CLI) handleIPSWhitelistRemove(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips whitelist-remove <ip>")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ips/whitelist/remove?ip=%s", url.QueryEscape(ip))
	_, err := cli.client.Delete(ctx, endpoint)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed IP from whitelist: %s\n", ip)
	return nil
}

func (cli *CLI) handleGeoIPCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips geoip-check <ip> [service]")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	service := "web"
	if len(args) > 1 {
		service = args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/geoip/check?ip=%s&service=%s",
		url.QueryEscape(ip), url.QueryEscape(service))

	data, err := cli.client.Get(ctx, endpoint)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing GeoIP response: %w", err)
	}

	fmt.Printf("GeoIP Check for %s (service: %s):\n", ip, service)
	cli.printKeyValue(result, "  ")
	return nil
}

func (cli *CLI) handleVPNCheck(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: qff-cli ips vpn-check <ip>")
	}

	ip := args[0]
	if err := validateIP(ip); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/geoip/vpn-check?ip=%s", url.QueryEscape(ip))
	data, err := cli.client.Get(ctx, endpoint)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing VPN check response: %w", err)
	}

	fmt.Printf("VPN/Proxy Check for %s:\n", ip)
	cli.printKeyValue(result, "  ")
	return nil
}

func (cli *CLI) handleServiceRules(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/geoip/service-rules")
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing service rules response: %w", err)
	}

	fmt.Println("Service Rules:")
	cli.printKeyValue(result, "  ")
	return nil
}

// Ports command handlers
func (cli *CLI) handlePorts(args []string) error {
	if len(args) == 0 {
		return cli.showPortsUsage()
	}

	portsCommands := map[string]func([]string) error{
		"list":   cli.handlePortsList,
		"add":    cli.handlePortsAdd,
		"remove": cli.handlePortsRemove,
	}

	subcommand := args[0]
	handler, exists := portsCommands[subcommand]
	if !exists {
		return fmt.Errorf("unknown ports command: %s", subcommand)
	}

	return handler(args[1:])
}

func (cli *CLI) showPortsUsage() error {
	fmt.Println("Port Management Commands:")
	fmt.Println("  ports list                                    List all configured port rules")
	fmt.Println("  ports add <port> <tcp|udp> <in|out> [action]  Add port rule")
	fmt.Println("  ports remove <port> <tcp|udp> <in|out>        Remove port rule")
	fmt.Println("\nExamples:")
	fmt.Println("  qff-cli ports add 8080 tcp in allow")
	fmt.Println("  qff-cli ports add 53 udp out allow")
	fmt.Println("  qff-cli ports add 23 tcp in deny")
	fmt.Println("  qff-cli ports remove 8080 tcp in")
	return nil
}

func (cli *CLI) handlePortsList(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	data, err := cli.client.Get(ctx, "/api/ports/list")
	if err != nil {
		return err
	}

	var result PortRulesResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing port rules response: %w", err)
	}

	cli.printPortRules(&result)
	return nil
}

func (cli *CLI) handlePortsAdd(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: qff-cli ports add <port> <tcp|udp> <in|out> [action]")
	}

	port := args[0]
	protocol := args[1]
	direction := args[2]
	action := "allow"

	if len(args) > 3 {
		action = args[3]
	}

	if err := validatePortRule(port, protocol, direction, action); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ports/add?port=%s&protocol=%s&direction=%s&action=%s",
		url.QueryEscape(port), protocol, direction, action)

	_, err := cli.client.Post(ctx, endpoint, nil)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully added port rule: %s/%s %s %s\n", port, protocol, direction, action)
	return nil
}

func (cli *CLI) handlePortsRemove(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: qff-cli ports remove <port> <tcp|udp> <in|out>")
	}

	port := args[0]
	protocol := args[1]
	direction := args[2]

	if err := validatePortRule(port, protocol, direction, ""); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cli.config.Timeout)
	defer cancel()

	endpoint := fmt.Sprintf("/api/ports/remove?port=%s&protocol=%s&direction=%s",
		url.QueryEscape(port), protocol, direction)

	_, err := cli.client.Delete(ctx, endpoint)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully removed port rule: %s/%s %s\n", port, protocol, direction)
	return nil
}

// Utility functions and types
func validateIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	// Add more sophisticated IP validation here if needed
	return nil
}

func validatePortRule(port, protocol, direction, action string) error {
	if port == "" {
		return fmt.Errorf("port cannot be empty")
	}

	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port number: %s", port)
	}

	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("protocol must be 'tcp' or 'udp'")
	}

	if direction != "in" && direction != "out" {
		return fmt.Errorf("direction must be 'in' or 'out'")
	}

	if action != "" && action != "allow" && action != "deny" {
		return fmt.Errorf("action must be 'allow' or 'deny'")
	}

	return nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Response types
type StatusResponse struct {
	Status           string `json:"status"`
	Version          string `json:"version"`
	Uptime           string `json:"uptime"`
	GeoIPAvailable   bool   `json:"geoip_available"`
	TemporaryEntries int    `json:"temporary_entries"`
}

type MetricsResponse struct {
	SystemMetrics   map[string]float64     `json:"system_metrics"`
	FirewallMetrics map[string]interface{} `json:"firewall_metrics"`
}

type BlockedIPsResponse struct {
	BlockedIPs map[string]BlockedIPDetail `json:"blocked_ips"`
}

type BlockedIPDetail struct {
	Reason    string `json:"reason"`
	Service   string `json:"service"`
	BlockTime string `json:"block_time"`
}

type WhitelistResponse struct {
	WhitelistedIPs map[string]WhitelistDetail `json:"whitelisted_ips"`
}

type WhitelistDetail struct {
	Reason    string `json:"reason"`
	Permanent bool   `json:"permanent"`
	AddedTime string `json:"added_time"`
}

type PortRulesResponse struct {
	PortRules map[string]interface{} `json:"port_rules"`
}

// Print functions
func (cli *CLI) printStatus(status *StatusResponse) {
	fmt.Printf("Status: %s\n", status.Status)
	fmt.Printf("Version: %s\n", status.Version)
	fmt.Printf("Uptime: %s\n", status.Uptime)
	fmt.Printf("GeoIP Available: %t\n", status.GeoIPAvailable)
	fmt.Printf("Temporary Entries: %d\n", status.TemporaryEntries)
}

func (cli *CLI) printMetrics(metrics *MetricsResponse) {
	fmt.Println("System Metrics:")
	for key, value := range metrics.SystemMetrics {
		fmt.Printf("  %s: %.2f\n", key, value)
	}

	fmt.Println("Firewall Metrics:")
	cli.printKeyValue(metrics.FirewallMetrics, "  ")
}

func (cli *CLI) printBlockedIPs(response *BlockedIPsResponse) {
	fmt.Printf("Blocked IPs (%d):\n", len(response.BlockedIPs))
	for ip, details := range response.BlockedIPs {
		fmt.Printf("  %s: %s (%s) - %s\n", ip, details.Reason, details.Service, details.BlockTime)
	}
}

func (cli *CLI) printWhitelist(response *WhitelistResponse) {
	fmt.Printf("Whitelisted IPs (%d):\n", len(response.WhitelistedIPs))
	for ip, details := range response.WhitelistedIPs {
		permanent := "temporary"
		if details.Permanent {
			permanent = "permanent"
		}
		fmt.Printf("  %s: %s (%s) - %s\n", ip, details.Reason, permanent, details.AddedTime)
	}
}

func (cli *CLI) printPortRules(response *PortRulesResponse) {
	fmt.Println("Current Port Rules:")
	cli.printKeyValue(response.PortRules, "  ")
}

func (cli *CLI) printIPList(listType string, result map[string]interface{}) {
	fmt.Printf("%s entries:\n", strings.Title(listType))
	cli.printKeyValue(result, "  ")
}

func (cli *CLI) printKeyValue(data map[string]interface{}, indent string) {
	for key, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			fmt.Printf("%s%s:\n", indent, key)
			cli.printKeyValue(v, indent+"  ")
		case []interface{}:
			fmt.Printf("%s%s: [%d items]\n", indent, key, len(v))
			for i, item := range v {
				fmt.Printf("%s  [%d]: %v\n", indent, i, item)
			}
		case float64:
			fmt.Printf("%s%s: %.2f\n", indent, key, v)
		default:
			fmt.Printf("%s%s: %v\n", indent, key, v)
		}
	}
}
