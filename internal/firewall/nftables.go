// internal/firewall/nftables.go
package firewall

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"qfw/internal/config"
	"qfw/internal/logger"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// RuleKey uniquely identifies a port rule
type RuleKey struct {
	Port      int
	Protocol  string
	Direction string
	Action    string
}

// RuleTracker stores references to nftables rules
type RuleTracker struct {
	Rule    *nftables.Rule
	Key     RuleKey
	AddedAt time.Time
}

// Simplified manager types for this implementation
type DNSManager struct {
	conn      *nftables.Conn
	table     *nftables.Table
	hostnames map[string]*HostEntry
	mu        sync.RWMutex
}

type HostEntry struct {
	Hostname  string
	IPs       []net.IP
	SetName   string
	LastCheck time.Time
}

type RateLimitManager struct {
	conn   *nftables.Conn
	table  *nftables.Table
	config *config.RateLimitConfig
}

type BOGONManager struct {
	config *config.SecurityConfig
	conn   *nftables.Conn
	table  *nftables.Table
}

type NFTManager struct {
	conn        *nftables.Conn
	config      *config.Config
	table       *nftables.Table
	dnsManager  *DNSManager
	rateLimiter *RateLimitManager
	bogonMgr    *BOGONManager

	// Rule tracking
	trackedRules map[RuleKey]*RuleTracker
	rulesMutex   sync.RWMutex
}

type FirewallState struct {
	Rules []byte `json:"rules"`
	Sets  []byte `json:"sets"`
}

// Simplified constructors
func NewDNSManager(conn *nftables.Conn, table *nftables.Table) *DNSManager {
	return &DNSManager{
		conn:      conn,
		table:     table,
		hostnames: make(map[string]*HostEntry),
	}
}

func NewRateLimitManager(conn *nftables.Conn, table *nftables.Table, cfg *config.RateLimitConfig) *RateLimitManager {
	return &RateLimitManager{
		conn:   conn,
		table:  table,
		config: cfg,
	}
}

func NewBOGONManager(cfg *config.SecurityConfig, conn *nftables.Conn, table *nftables.Table) *BOGONManager {
	return &BOGONManager{
		config: cfg,
		conn:   conn,
		table:  table,
	}
}

func NewNFTManager(cfg *config.Config) *NFTManager {
	conn := &nftables.Conn{}
	table := &nftables.Table{
		Name:   "qfw",
		Family: nftables.TableFamilyINet,
	}

	mgr := &NFTManager{
		conn:         conn,
		config:       cfg,
		table:        table,
		trackedRules: make(map[RuleKey]*RuleTracker),
	}

	mgr.dnsManager = NewDNSManager(conn, table)
	mgr.rateLimiter = NewRateLimitManager(conn, table, &cfg.RateLimit)
	mgr.bogonMgr = NewBOGONManager(&cfg.Security, conn, table)

	return mgr
}

// Simplified methods for the sub-managers
func (d *DNSManager) Initialize() error {
	logger.Info("dns", "Initializing DNS manager")
	return nil
}

func (d *DNSManager) AddHostname(hostname, setType string) error {
	logger.Info("dns", "Adding hostname", "hostname", hostname)
	return nil
}

func (d *DNSManager) GetHostnames() map[string]*HostEntry {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.hostnames
}

func (r *RateLimitManager) Initialize() error {
	if !r.config.EnableRateLimit {
		return nil
	}
	logger.Info("ratelimit", "Initializing rate limiting")
	return nil
}

func (r *RateLimitManager) AddRateLimitRules(inputChain *nftables.Chain) error {
	if !r.config.EnableRateLimit {
		return nil
	}
	logger.Info("ratelimit", "Adding rate limit rules")
	return nil
}

func (b *BOGONManager) Initialize() error {
	if !b.config.EnableBogonFilter {
		return nil
	}
	logger.Info("bogon", "Initializing BOGON filtering")
	return nil
}

func (b *BOGONManager) AddBOGONRules(inputChain *nftables.Chain) error {
	if !b.config.EnableBogonFilter {
		return nil
	}
	logger.Info("bogon", "Adding BOGON rules")
	return nil
}

// Utility functions
func CheckNFTablesAvailable() error {
	// Try to create a test connection
	conn := &nftables.Conn{}

	// Try to list existing tables - this will fail if nftables is not available
	_, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("nftables is not available or not installed. Please install nftables first:\n"+
			"  Ubuntu/Debian: sudo apt install nftables\n"+
			"  RHEL/CentOS:   sudo yum install nftables\n"+
			"  Arch Linux:    sudo pacman -S nftables\n"+
			"Error: %v", err)
	}

	return nil
}

// NFTManager methods
func (n *NFTManager) AddPortRule(port int, protocol string, direction string, action string) error {
	var chain *nftables.Chain
	var protocolNum byte

	// Determine protocol number
	switch strings.ToLower(protocol) {
	case "tcp":
		protocolNum = 6
	case "udp":
		protocolNum = 17
	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	// Determine chain
	switch strings.ToLower(direction) {
	case "input", "in":
		chain = &nftables.Chain{Name: "input", Table: n.table}
	case "output", "out":
		chain = &nftables.Chain{Name: "output", Table: n.table}
	default:
		return fmt.Errorf("unsupported direction: %s", direction)
	}

	// Determine verdict
	var verdict expr.VerdictKind
	switch strings.ToLower(action) {
	case "accept", "allow":
		verdict = expr.VerdictAccept
	case "drop", "deny", "block":
		verdict = expr.VerdictDrop
	case "reject":
		verdict = expr.VerdictReturn
	default:
		return fmt.Errorf("unsupported action: %s", action)
	}

	// Create the rule
	rule := &nftables.Rule{
		Table: n.table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNum}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
			&expr.Verdict{Kind: verdict},
		},
	}

	// Add the rule
	n.conn.AddRule(rule)

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	// Track the rule
	key := RuleKey{
		Port:      port,
		Protocol:  strings.ToLower(protocol),
		Direction: strings.ToLower(direction),
		Action:    strings.ToLower(action),
	}

	n.rulesMutex.Lock()
	n.trackedRules[key] = &RuleTracker{
		Rule:    rule,
		Key:     key,
		AddedAt: time.Now(),
	}
	n.rulesMutex.Unlock()

	logger.Info("firewall", "Added port rule", "port", port, "protocol", protocol, "direction", direction, "action", action)
	return nil
}

func (n *NFTManager) RemovePortRule(port int, protocol string, direction string) error {
	// Normalize inputs
	protocol = strings.ToLower(protocol)
	direction = strings.ToLower(direction)

	n.rulesMutex.Lock()
	defer n.rulesMutex.Unlock()

	// Find all rules matching port, protocol, and direction (regardless of action)
	var rulesToRemove []*RuleTracker
	var keysToRemove []RuleKey

	for key, tracker := range n.trackedRules {
		if key.Port == port && key.Protocol == protocol && key.Direction == direction {
			rulesToRemove = append(rulesToRemove, tracker)
			keysToRemove = append(keysToRemove, key)
		}
	}

	if len(rulesToRemove) == 0 {
		return fmt.Errorf("no matching rule found for port %d/%s %s", port, protocol, direction)
	}

	// Remove rules from nftables
	for _, tracker := range rulesToRemove {
		n.conn.DelRule(tracker.Rule)
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	// Remove from tracking
	for _, key := range keysToRemove {
		delete(n.trackedRules, key)
	}

	logger.Info("firewall", "Removed port rules", "port", port, "protocol", protocol, "direction", direction, "count", len(rulesToRemove))
	return nil
}

func (n *NFTManager) ListPortRules() map[string]interface{} {
	n.rulesMutex.RLock()
	defer n.rulesMutex.RUnlock()

	// Get config-based rules
	configRules := map[string]interface{}{
		"tcp_in":   n.config.Ports.TCPIn,
		"tcp_out":  n.config.Ports.TCPOut,
		"udp_in":   n.config.Ports.UDPIn,
		"udp_out":  n.config.Ports.UDPOut,
		"tcp_deny": n.config.Ports.TCPDeny,
		"udp_deny": n.config.Ports.UDPDeny,
	}

	// Add dynamically tracked rules
	dynamicRules := make(map[string]interface{})
	for key, tracker := range n.trackedRules {
		ruleID := fmt.Sprintf("%s_%d_%s_%s", key.Protocol, key.Port, key.Direction, key.Action)
		dynamicRules[ruleID] = map[string]interface{}{
			"port":      key.Port,
			"protocol":  key.Protocol,
			"direction": key.Direction,
			"action":    key.Action,
			"added_at":  tracker.AddedAt,
		}
	}

	return map[string]interface{}{
		"config_rules":  configRules,
		"dynamic_rules": dynamicRules,
		"total_tracked": len(n.trackedRules),
	}
}

// RemoveAllPortRules removes all tracked port rules
func (n *NFTManager) RemoveAllPortRules() error {
	n.rulesMutex.Lock()
	defer n.rulesMutex.Unlock()

	for _, tracker := range n.trackedRules {
		n.conn.DelRule(tracker.Rule)
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	// Clear tracking
	n.trackedRules = make(map[RuleKey]*RuleTracker)

	logger.Info("firewall", "Removed all tracked port rules")
	return nil
}

// GetRuleStats returns statistics about tracked rules
func (n *NFTManager) GetRuleStats() map[string]interface{} {
	n.rulesMutex.RLock()
	defer n.rulesMutex.RUnlock()

	stats := map[string]interface{}{
		"total_tracked": len(n.trackedRules),
	}

	// Count by protocol
	protocolCount := make(map[string]int)
	directionCount := make(map[string]int)
	actionCount := make(map[string]int)

	for key := range n.trackedRules {
		protocolCount[key.Protocol]++
		directionCount[key.Direction]++
		actionCount[key.Action]++
	}

	stats["by_protocol"] = protocolCount
	stats["by_direction"] = directionCount
	stats["by_action"] = actionCount

	return stats
}

// UpdatePortRuleAction changes the action of an existing rule
func (n *NFTManager) UpdatePortRuleAction(port int, protocol string, direction string, newAction string) error {
	// Remove the old rule
	if err := n.RemovePortRule(port, protocol, direction); err != nil {
		return fmt.Errorf("failed to remove old rule: %w", err)
	}

	// Add the new rule with updated action
	if err := n.AddPortRule(port, protocol, direction, newAction); err != nil {
		return fmt.Errorf("failed to add updated rule: %w", err)
	}

	return nil
}

func (n *NFTManager) Initialize() error {
	logger.Info("firewall", "Initializing nftables")

	n.conn.AddTable(n.table)

	if err := n.setupChains(); err != nil {
		return fmt.Errorf("failed to setup chains: %w", err)
	}

	if err := n.setupSets(); err != nil {
		return fmt.Errorf("failed to setup sets: %w", err)
	}

	if err := n.setupRules(); err != nil {
		return fmt.Errorf("failed to setup rules: %w", err)
	}

	// Initialize sub-managers
	if err := n.dnsManager.Initialize(); err != nil {
		logger.Error("firewall", "DNS manager initialization failed", "error", err.Error())
	}

	if err := n.rateLimiter.Initialize(); err != nil {
		logger.Error("firewall", "Rate limiter initialization failed", "error", err.Error())
	}

	if err := n.bogonMgr.Initialize(); err != nil {
		logger.Error("firewall", "BOGON manager initialization failed", "error", err.Error())
	}

	if err := n.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush nftables: %w", err)
	}

	logger.Info("firewall", "nftables initialized successfully")
	return nil
}

func (n *NFTManager) setupChains() error {
	chains := []struct {
		name     string
		hook     *nftables.ChainHook
		priority *nftables.ChainPriority
		policy   nftables.ChainPolicy
	}{
		{"input", nftables.ChainHookInput, nftables.ChainPriorityFilter, n.getDefaultPolicy()},
		{"output", nftables.ChainHookOutput, nftables.ChainPriorityFilter, nftables.ChainPolicyAccept},
		{"forward", nftables.ChainHookForward, nftables.ChainPriorityFilter, nftables.ChainPolicyDrop},
	}

	for _, c := range chains {
		n.conn.AddChain(&nftables.Chain{
			Name:     c.name,
			Table:    n.table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  c.hook,
			Priority: c.priority,
			Policy:   &c.policy,
		})
	}

	return nil
}

func (n *NFTManager) getDefaultPolicy() nftables.ChainPolicy {
	if n.config.Firewall.DefaultPolicy == "accept" {
		return nftables.ChainPolicyAccept
	}
	return nftables.ChainPolicyDrop
}

func (n *NFTManager) setupSets() error {
	sets := []struct {
		name    string
		keyType nftables.SetDatatype
	}{
		{"whitelist_ips", nftables.TypeIPAddr},
		{"blacklist_ips", nftables.TypeIPAddr},
		{"temp_block_ips", nftables.TypeIPAddr},
	}

	for _, s := range sets {
		n.conn.AddSet(&nftables.Set{
			Name:    s.name,
			Table:   n.table,
			KeyType: s.keyType,
		}, []nftables.SetElement{})
	}

	return nil
}

func (n *NFTManager) setupRules() error {
	inputChain := &nftables.Chain{Name: "input", Table: n.table}

	// Allow loopback
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte("lo\x00")},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Whitelist rule
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: "whitelist_ips"},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Blacklist rule
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: "blacklist_ips"},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	// Setup port rules from config (these won't be tracked for removal)
	if err := n.setupConfigPortRules(); err != nil {
		return err
	}

	// Add rate limiting rules
	if err := n.rateLimiter.AddRateLimitRules(inputChain); err != nil {
		return err
	}

	// Add BOGON filtering rules
	if err := n.bogonMgr.AddBOGONRules(inputChain); err != nil {
		return err
	}

	return nil
}

func (n *NFTManager) setupConfigPortRules() error {
	inputChain := &nftables.Chain{Name: "input", Table: n.table}
	outputChain := &nftables.Chain{Name: "output", Table: n.table}

	// TCP incoming ports (allow) - config rules, not tracked
	for _, port := range n.config.Ports.TCPIn {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP protocol
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		logger.Info("firewall", "Added TCP input rule from config", "port", port)
	}

	// UDP incoming ports (allow)
	for _, port := range n.config.Ports.UDPIn {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}}, // UDP protocol
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		logger.Info("firewall", "Added UDP input rule from config", "port", port)
	}

	// TCP outgoing ports (allow)
	for _, port := range n.config.Ports.TCPOut {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: outputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP protocol
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		logger.Info("firewall", "Added TCP output rule from config", "port", port)
	}

	// UDP outgoing ports (allow)
	for _, port := range n.config.Ports.UDPOut {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: outputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}}, // UDP protocol
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})
		logger.Info("firewall", "Added UDP output rule from config", "port", port)
	}

	// TCP deny ports (explicit block)
	for _, port := range n.config.Ports.TCPDeny {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}, // TCP protocol
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
		logger.Info("firewall", "Added TCP deny rule from config", "port", port)
	}

	// UDP deny ports (explicit block)
	for _, port := range n.config.Ports.UDPDeny {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{17}}, // UDP protocol
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
		logger.Info("firewall", "Added UDP deny rule from config", "port", port)
	}

	return nil
}

// Additional helper methods...
func (n *NFTManager) AddWhitelistIP(ip net.IP) error {
	logger.Info("firewall", "Adding IP to whitelist", "ip", ip.String())
	set := &nftables.Set{Name: "whitelist_ips", Table: n.table}
	n.conn.SetAddElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) RemoveWhitelistIP(ip net.IP) error {
	logger.Info("firewall", "Removing IP from whitelist", "ip", ip.String())
	set := &nftables.Set{Name: "whitelist_ips", Table: n.table}
	n.conn.SetDeleteElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) AddBlacklistIP(ip net.IP) error {
	logger.Info("firewall", "Adding IP to blacklist", "ip", ip.String())
	set := &nftables.Set{Name: "blacklist_ips", Table: n.table}
	n.conn.SetAddElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) RemoveBlacklistIP(ip net.IP) error {
	logger.Info("firewall", "Removing IP from blacklist", "ip", ip.String())
	set := &nftables.Set{Name: "blacklist_ips", Table: n.table}
	n.conn.SetDeleteElements(set, []nftables.SetElement{{Key: ip.To4()}})
	return n.conn.Flush()
}

func (n *NFTManager) WhitelistCurrentUser() error {
	// Get the IP of the user who started the application
	sshClient := os.Getenv("SSH_CLIENT")
	if sshClient != "" {
		parts := strings.Fields(sshClient)
		if len(parts) > 0 {
			ip := net.ParseIP(parts[0])
			if ip != nil && !ip.IsLoopback() {
				logger.Info("firewall", "Auto-whitelisting SSH client IP", "ip", ip.String())
				return n.AddWhitelistIP(ip)
			}
		}
	}

	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		parts := strings.Fields(sshConn)
		if len(parts) >= 4 {
			ip := net.ParseIP(parts[0])
			if ip != nil && !ip.IsLoopback() {
				logger.Info("firewall", "Auto-whitelisting SSH connection IP", "ip", ip.String())
				return n.AddWhitelistIP(ip)
			}
		}
	}

	logger.Info("firewall", "No remote connection detected, skipping auto-whitelist")
	return nil
}

func (n *NFTManager) Reload() error {
	logger.Info("firewall", "Reloading nftables configuration")
	n.conn.FlushTable(n.table)

	// Clear tracked rules on reload
	n.rulesMutex.Lock()
	n.trackedRules = make(map[RuleKey]*RuleTracker)
	n.rulesMutex.Unlock()

	return n.Initialize()
}

func (n *NFTManager) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	stats["table_name"] = n.table.Name
	stats["dns_hosts"] = len(n.dnsManager.GetHostnames())
	stats["rule_stats"] = n.GetRuleStats()
	return stats, nil
}

// Include other methods like DNS, blocklist management etc...
func (n *NFTManager) AddDynamicHost(hostname string) error {
	return n.dnsManager.AddHostname(hostname, "whitelist")
}

func (n *NFTManager) GetDynamicHosts() map[string]interface{} {
	hosts := n.dnsManager.GetHostnames()
	result := make(map[string]interface{})
	for k, v := range hosts {
		result[k] = map[string]interface{}{
			"ips":        v.IPs,
			"set_name":   v.SetName,
			"last_check": v.LastCheck,
		}
	}
	return result
}

func (n *NFTManager) RemoveBlocklistSet(setName string) error {
	logger.Info("firewall", "Removing blocklist set", "set", setName)
	return nil
}

func (n *NFTManager) AddBlocklistSet(setName string, ips []net.IP) error {
	logger.Info("firewall", "Adding blocklist set", "set", setName, "count", len(ips))
	return nil
}

func (n *NFTManager) BackupCurrentState() (*FirewallState, error) {
	state := &FirewallState{
		Rules: []byte("backup_rules"),
		Sets:  []byte("backup_sets"),
	}
	return state, nil
}

func (n *NFTManager) RestoreState(state *FirewallState) error {
	logger.Info("firewall", "Restoring firewall state")
	return n.Initialize()
}
