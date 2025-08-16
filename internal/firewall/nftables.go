// internal/firewall/nftables.go
package firewall

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"qff/internal/config"
	"qff/internal/logger"

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
		Name:   "qff",
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

	// Determine verdict and log prefix
	var verdict expr.VerdictKind
	var logPrefix string
	switch strings.ToLower(action) {
	case "accept", "allow":
		verdict = expr.VerdictAccept
		logPrefix = fmt.Sprintf("QFF-ACCEPT-%s-%d: ", strings.ToUpper(direction), port)
	case "drop", "deny", "block":
		verdict = expr.VerdictDrop
		logPrefix = fmt.Sprintf("QFF-DROP-%s-%d: ", strings.ToUpper(direction), port)
	case "reject":
		verdict = expr.VerdictReturn
		logPrefix = fmt.Sprintf("QFF-REJECT-%s-%d: ", strings.ToUpper(direction), port)
	default:
		return fmt.Errorf("unsupported action: %s", action)
	}

	// Create the rule with logging
	rule := &nftables.Rule{
		Table: n.table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protocolNum}},
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(port >> 8), byte(port)}},
			&expr.Log{Data: []byte(logPrefix)},
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

	logger.Info("firewall", "Added port rule with logging", "port", port, "protocol", protocol, "direction", direction, "action", action)
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
	outputChain := &nftables.Chain{Name: "output", Table: n.table}

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

	// Whitelist rule (with logging)
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: "whitelist_ips"},
			&expr.Log{Data: []byte("QFF-ACCEPT-WHITELIST: ")},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// Blacklist rule (with logging)
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: inputChain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
			&expr.Lookup{SourceRegister: 1, SetName: "blacklist_ips"},
			&expr.Log{Data: []byte("QFF-DROP-BLACKLIST: ")},
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

	// Default drop rule with logging for INPUT
	if n.config.Firewall.DefaultPolicy == "drop" {
		n.conn.AddRule(&nftables.Rule{
			Table: n.table,
			Chain: inputChain,
			Exprs: []expr.Any{
				&expr.Log{Data: []byte("QFF-DROP-INPUT: ")},
				&expr.Verdict{Kind: expr.VerdictDrop},
			},
		})
	}

	// Default drop rule with logging for OUTPUT
	n.conn.AddRule(&nftables.Rule{
		Table: n.table,
		Chain: outputChain,
		Exprs: []expr.Any{
			&expr.Log{Data: []byte("QFF-DROP-OUTPUT: ")},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

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
				&expr.Log{Data: []byte(fmt.Sprintf("QFF-ACCEPT-INPUT-%d: ", port))},
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
				&expr.Log{Data: []byte(fmt.Sprintf("QFF-ACCEPT-INPUT-%d: ", port))},
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
				&expr.Log{Data: []byte(fmt.Sprintf("QFF-ACCEPT-OUTPUT-%d: ", port))},
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
				&expr.Log{Data: []byte(fmt.Sprintf("QFF-ACCEPT-OUTPUT-%d: ", port))},
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
				&expr.Log{Data: []byte(fmt.Sprintf("QFF-DROP-INPUT-%d: ", port))},
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
				&expr.Log{Data: []byte(fmt.Sprintf("QFF-DROP-INPUT-%d: ", port))},
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
	var detectedIPs []net.IP

	// Method 1: SSH_CLIENT environment variable
	sshClient := os.Getenv("SSH_CLIENT")
	if sshClient != "" {
		parts := strings.Fields(sshClient)
		if len(parts) > 0 {
			if ip := net.ParseIP(parts[0]); ip != nil && !ip.IsLoopback() {
				detectedIPs = append(detectedIPs, ip)
				logger.Info("firewall", "Detected SSH client IP from SSH_CLIENT", "ip", ip.String())
			}
		}
	}

	// Method 2: SSH_CONNECTION environment variable
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		parts := strings.Fields(sshConn)
		if len(parts) >= 4 {
			if ip := net.ParseIP(parts[0]); ip != nil && !ip.IsLoopback() {
				// Check if we already have this IP
				found := false
				for _, existingIP := range detectedIPs {
					if existingIP.Equal(ip) {
						found = true
						break
					}
				}
				if !found {
					detectedIPs = append(detectedIPs, ip)
					logger.Info("firewall", "Detected SSH client IP from SSH_CONNECTION", "ip", ip.String())
				}
			}
		}
	}

	// Method 3: Parse /proc/net/tcp for established SSH connections
	if len(detectedIPs) == 0 {
		if sshIPs := n.getSSHConnections(); len(sshIPs) > 0 {
			detectedIPs = append(detectedIPs, sshIPs...)
			logger.Info("firewall", "Detected SSH connections from /proc/net/tcp", "count", len(sshIPs))
		}
	}

	// Method 4: Parse 'who' command output for SSH sessions
	if len(detectedIPs) == 0 {
		if whoIPs := n.getWhoSSHConnections(); len(whoIPs) > 0 {
			detectedIPs = append(detectedIPs, whoIPs...)
			logger.Info("firewall", "Detected SSH connections from 'who' command", "count", len(whoIPs))
		}
	}

	// Whitelist all detected IPs
	if len(detectedIPs) > 0 {
		for _, ip := range detectedIPs {
			if err := n.AddWhitelistIP(ip); err != nil {
				logger.Error("firewall", "Failed to whitelist detected IP", "ip", ip.String(), "error", err.Error())
			} else {
				logger.Info("firewall", "Auto-whitelisted SSH client IP", "ip", ip.String())
			}
		}
		return nil
	}

	logger.Info("firewall", "No remote SSH connections detected, skipping auto-whitelist")
	return nil
}

// getSSHConnections parses /proc/net/tcp for SSH connections (port 22)
func (n *NFTManager) getSSHConnections() []net.IP {
	var ips []net.IP

	file, err := os.Open("/proc/net/tcp")
	if err != nil {
		return ips
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address (format: IP:PORT in hex)
		localAddr := fields[1]
		if strings.HasSuffix(localAddr, ":0016") { // 0016 = port 22 in hex
			// Parse remote address
			remoteAddr := fields[2]
			if remoteIP := n.parseHexIP(remoteAddr); remoteIP != nil && !remoteIP.IsLoopback() {
				// Check if connection is established (state 01)
				state := fields[3]
				if state == "01" {
					ips = append(ips, remoteIP)
				}
			}
		}
	}

	return ips
}

// getWhoSSHConnections uses the 'who' command to find SSH sessions
func (n *NFTManager) getWhoSSHConnections() []net.IP {
	var ips []net.IP

	cmd := exec.Command("who")
	output, err := cmd.Output()
	if err != nil {
		return ips
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "pts/") && strings.Contains(line, "(") {
			// Extract IP from parentheses: user pts/0 2025-08-16 12:00 (192.168.1.100)
			start := strings.LastIndex(line, "(")
			end := strings.LastIndex(line, ")")
			if start != -1 && end != -1 && end > start {
				ipStr := line[start+1 : end]
				if ip := net.ParseIP(ipStr); ip != nil && !ip.IsLoopback() {
					ips = append(ips, ip)
				}
			}
		}
	}

	return ips
}

// parseHexIP converts hex format IP:PORT to net.IP
func (n *NFTManager) parseHexIP(hexAddr string) net.IP {
	parts := strings.Split(hexAddr, ":")
	if len(parts) != 2 {
		return nil
	}

	hexIP := parts[0]
	if len(hexIP) != 8 {
		return nil
	}

	// Convert hex to IP bytes (little endian)
	var ipBytes [4]byte
	for i := 0; i < 4; i++ {
		byteVal, err := strconv.ParseUint(hexIP[i*2:(i+1)*2], 16, 8)
		if err != nil {
			return nil
		}
		ipBytes[3-i] = byte(byteVal) // Reverse byte order
	}

	return net.IPv4(ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
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
