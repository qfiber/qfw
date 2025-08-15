# QFW - qFibre Firewall Manager

[![License: GPLv3](https://img.shields.io/badge/license-%20%20GNU%20GPLv3%20-blue)](https://opensource.org/license/gpl-3-0)
[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-green.svg)](https://www.linux.org/)

QFW (qFibre Firewall) is a modern, high-performance firewall management solution that serves as a superior replacement for CSF (ConfigServer Security & Firewall). Built with Go and leveraging nftables, QFW provides enterprise-grade security features, real-time monitoring, and comprehensive API management.

## Introduction

QFW combines the simplicity of CSF with the power of modern technologies to deliver:

- **Modern Architecture**: Built on nftables for superior performance vs iptables
- **REST API**: Complete programmatic control and automation
- **Real-time Monitoring**: Live metrics, resource monitoring, and alerting
- **Advanced Security**: SYN flood protection, rate limiting, BOGON/Martian filtering
- **Geographic Filtering**: Country-based blocking with offline GeoIP
- **Smart Notifications**: Email and webhook alerts (Slack, Discord, n8n, ...)
- **Test Mode**: Safe rule testing with auto-revert functionality
- **Container Ready**: Docker and Kubernetes compatible
- **High Performance**: Efficient nftables sets for O(1) IP lookups

### Key Features

- ✅ **Complete CSF replacement** with 100%+ feature parity
- ✅ **TCP/UDP port management** with real-time API control
- ✅ **IP whitelist/blacklist** with automatic management
- ✅ **Geographic filtering** (country blocking/allowing)
- ✅ **Rate limiting** per IP and per port
- ✅ **SYN flood protection** with multi-layer defense
- ✅ **fail2ban integration** with bidirectional API
- ✅ **Dynamic DNS support** with automatic IP updates
- ✅ **Resource monitoring** with configurable alerts
- ✅ **Test mode** with automatic revert for safe changes
- ✅ **BOGON and Martian packet filtering**
- ✅ **Webhook notifications** for modern alerting

## Dependencies

Before installing QFW, ensure your system has the following dependencies:

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+)
- **Architecture**: x86_64 or ARM64
- **Kernel**: Linux 5.4+ (for nftables support)
- **RAM**: Minimum 512MB, Recommended 1GB+
- **Disk**: 100MB for installation, additional space for logs

### Required Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y nftables golang-1.22 git build-essential curl jq

# CentOS/RHEL/AlmaLinux
sudo dnf install -y nftables golang git gcc curl jq

# Enable and start nftables
sudo systemctl enable nftables
sudo systemctl start nftables
```

### Optional Dependencies

```bash
# For fail2ban integration
sudo apt install -y fail2ban  # Ubuntu/Debian
sudo dnf install -y fail2ban  # CentOS/RHEL

# For enhanced monitoring and testing
sudo apt install -y hping3 netcat-openbsd  # Ubuntu/Debian
sudo dnf install -y hping3 nc              # CentOS/RHEL

# For email notifications
sudo apt install -y mailutils  # Ubuntu/Debian
sudo dnf install -y mailx      # CentOS/RHEL
```

### Go Installation (if not available)

```bash
# Install Go 1.22+ if not available via package manager
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/qfw.git
cd qfw

# Build and install
make build install systemd

# Download GeoIP database (requires MaxMind license key)
export MAXMIND_LICENSE_KEY="your_maxmind_license_key"
sudo make geoip-download

# Start the service
sudo systemctl start qfw
sudo systemctl enable qfw
```


### Post-Installation Setup

```bash
# Install advanced features
sudo qfw-advanced install

# Install fail2ban integration
sudo qfw-cli f2b-install

# Enable all security features
sudo qfw-cli syn-enable
sudo qfw-cli bogon-enable
sudo qfw-cli martian-enable
sudo qfw-cli rate-enable

# Check status
qfw-cli status
```

## ⚙️ Configuration

### Main Configuration File

Edit the main configuration file at `/etc/qfw/qfw.conf`:

```ini
[firewall]
default_policy=drop
enable_ipv6=true

[ports]
# Incoming ports (SSH, HTTP, HTTPS)
tcp_in=22,80,443
tcp_out=53,80,443,993,995
udp_in=53,123
udp_out=53,123

# Explicitly denied ports
tcp_deny=23,135,139,445,1433,3389
udp_deny=137,138,161,1434

[security]
# Enable advanced security filtering
enable_bogon_filter=true
enable_martian_filter=true
bogon_update_interval=24h

[geoip]
mmdb_path=/etc/qfw/GeoLite2-Country.mmdb
country_block_file=/etc/qfw/countries.block
country_allow_file=/etc/qfw/countries.allow

[ratelimit]
enable_rate_limit=true
global_conn_limit=100
global_conn_window=1m
port_specific_limits=22:5/1m:tcp,80:50/1m:tcp,443:50/1m:tcp

[synflood]
enable_protection=true
syn_rate_limit=10
syn_burst=5
conntrack_max=100

[notification]
# Email notifications
enable_email=true
email_server=smtp.gmail.com
email_port=587
email_user=your-email@gmail.com
email_password=your-app-password
email_to=admin@yourdomain.com

# Webhook notifications
enable_webhooks=true
webhook_urls=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
webhook_timeout=10

[monitor]
# Resource monitoring
enable_resource_monitoring=true
cpu_alert=true
cpu_threshold=2.0
cpu_duration=5m
memory_alert=true
memory_threshold=80.0
disk_alert=true
disk_threshold=85.0

[testmode]
# Safe testing mode
enable_test_mode=true
test_duration=5m
revert_on_failure=true
test_connections=8.8.8.8,1.1.1.1
```

### IP Lists Configuration

**Whitelist** (`/etc/qfw/whitelist.txt`):
```
# Trusted IPs and networks
192.168.1.0/24
10.0.0.0/8
your-office-ip/32
trusted-server.com
```

**Blacklist** (`/etc/qfw/blacklist.txt`):
```
# Blocked IPs and networks
198.51.100.0/24
malicious-ip/32

# Include external lists
include /etc/qfw/tor_exits.txt
include /etc/qfw/malware_ips.txt
```

**Country Blocking** (`/etc/qfw/countries.block`):
```
# Block these countries (ISO 2-letter codes)
CN
RU
KP
IR
```

**Country Allowing** (`/etc/qfw/countries.allow`):
```
# Allow these countries (overrides block list)
US
CA
GB
DE
FR
```

### After Configuration Changes

```bash
# Restart QFW to apply changes
sudo systemctl restart qfw

# Or reload configuration (for some changes)
sudo systemctl reload qfw

# Check status
qfw-cli status
```

## CLI Commands

QFW provides a comprehensive command-line interface for all operations:

### Basic Operations

```bash
# System status and information
qfw-cli status                    # Show firewall status
qfw-cli metrics                   # Show system metrics
qfw-cli logs [lines]              # Show recent logs (default: 50)

# Service management
qfw-cli reload                    # Reload configuration
qfw-cli enable                    # Enable and start service
qfw-cli disable                   # Stop and disable service
```

### IP Management

```bash
# Whitelist/Blacklist management
qfw-cli whitelist <ip>            # Add IP to whitelist
qfw-cli blacklist <ip>            # Add IP to blacklist

# Temporary IP management
qfw-cli temp-block <ip> [duration] [reason]     # Temporarily block IP
qfw-cli temp-allow <ip> [duration] [reason]     # Temporarily allow IP
qfw-cli temp-list                 # List temporary entries
qfw-cli temp-remove <ip>          # Remove temporary entry

# Examples
qfw-cli temp-block 192.168.1.100 30m "Suspicious activity"
qfw-cli temp-allow 203.0.113.5 2h "Maintenance window"
```

### Port Management

```bash
# Port configuration
qfw-cli ports-list                # List all port configurations

# TCP port management
qfw-cli tcp-in-add <ports> [--permanent]       # Add TCP input ports
qfw-cli tcp-in-remove <ports> [--permanent]    # Remove TCP input ports
qfw-cli tcp-out-add <ports> [--permanent]      # Add TCP output ports
qfw-cli tcp-out-remove <ports> [--permanent]   # Remove TCP output ports

# UDP port management
qfw-cli udp-in-add <ports> [--permanent]       # Add UDP input ports
qfw-cli udp-in-remove <ports> [--permanent]    # Remove UDP input ports
qfw-cli udp-out-add <ports> [--permanent]      # Add UDP output ports
qfw-cli udp-out-remove <ports> [--permanent]   # Remove UDP output ports

# Examples
qfw-cli tcp-in-add "8080,9000:9999" --permanent
qfw-cli udp-in-remove "161,162"
```

### Geographic Management

```bash
# Country-based filtering
qfw-cli country-block <country_code>           # Block country
qfw-cli country-allow <country_code>           # Allow country
qfw-cli geo-stats                              # Show geo statistics

# Country-specific port access
qfw-cli country-ports "US:tcp:22,80,443"      # Allow US access to specific ports
qfw-cli country-ports "CA:udp:53,123"         # Allow Canada UDP access

# Examples
qfw-cli country-block CN                       # Block China
qfw-cli country-allow US                       # Allow United States
```

### Security Features

```bash
# Rate limiting
qfw-cli rate-stats               # Show rate limiting statistics
qfw-cli rate-config              # Show rate limiting configuration
qfw-cli rate-enable              # Enable rate limiting
qfw-cli rate-disable             # Disable rate limiting
qfw-cli rate-monitor             # Monitor rate limits in real-time

# SYN flood protection
qfw-cli syn-stats                # Show SYN flood protection statistics
qfw-cli syn-config               # Show SYN flood configuration
qfw-cli syn-enable               # Enable SYN flood protection
qfw-cli syn-disable              # Disable SYN flood protection
qfw-cli syn-detect               # Detect potential SYN flood attacks
qfw-cli syn-monitor              # Monitor SYN flood in real-time
qfw-cli syn-emergency            # Emergency SYN flood response

# Security filtering
qfw-cli bogon-enable             # Enable BOGON filtering
qfw-cli bogon-disable            # Disable BOGON filtering
qfw-cli martian-enable           # Enable Martian packet filtering
qfw-cli martian-disable          # Disable Martian packet filtering
qfw-cli security-stats           # Show security filtering statistics
```

### Dynamic DNS

```bash
# DynDNS management
qfw-cli dyndns-status            # Show DynDNS status
qfw-cli dyndns-add <hostname>    # Add hostname to monitoring
qfw-cli dyndns-remove <hostname> # Remove hostname from monitoring
qfw-cli dyndns-update            # Force DynDNS update

# Examples
qfw-cli dyndns-add home.example.com
qfw-cli dyndns-add office.dyndns.org
```

### Resource Monitoring

```bash
# Resource monitoring
qfw-cli monitor-status           # Show resource monitoring status
qfw-cli monitor-alerts           # Show active resource alerts
qfw-cli monitor-thresholds       # Show configured thresholds

# Advanced monitoring (requires qfw-monitor script)
qfw-monitor status               # Detailed resource status
qfw-monitor monitor              # Real-time monitoring dashboard
qfw-monitor configure            # Configure monitoring thresholds
qfw-monitor test-alerts          # Generate test load for alerts
```

### Test Mode

```bash
# Test mode for safe rule changes
qfw-cli test-start [duration]    # Start test mode (default: 5m)
qfw-cli test-stop                # Stop test mode
qfw-cli test-status              # Show test mode status
qfw-cli test-revert              # Manually revert test mode

# Advanced test mode
qfw-monitor test-start 10m "8.8.8.8,1.1.1.1" "22,80,443"
qfw-monitor test-monitor         # Monitor active test mode
```

### Notifications

```bash
# Notification testing
qfw-cli notify-test              # Send test notification
qfw-cli webhook-test <url>       # Test specific webhook URL
qfw-monitor test-notifications   # Test all notification channels
```

### fail2ban Integration

```bash
# fail2ban management
qfw-cli f2b-status               # Show fail2ban status
qfw-cli f2b-banned               # List banned IPs
qfw-cli f2b-ban <ip> [reason]    # Ban IP via fail2ban
qfw-cli f2b-unban <ip>           # Unban IP via fail2ban
qfw-cli f2b-install              # Install fail2ban configuration
qfw-cli f2b-test                 # Test fail2ban integration
```

### Advanced Management

```bash
# Import/export
qfw-cli import <file>            # Import blocklist from file

# Testing and validation
qfw-cli test-ip <ip>             # Test if IP would be blocked

# Advanced features (requires qfw-advanced script)
qfw-advanced bogon enable        # Enable BOGON filtering
qfw-advanced country block CN    # Block country via advanced interface
qfw-advanced report              # Generate security report
qfw-advanced monitor             # Real-time performance monitoring
```

## API Commands

QFW provides a comprehensive REST API for programmatic control and automation:

### Base URL
```
http://localhost:8080
```

### Authentication
Currently, QFW API uses IP-based access control. Ensure your management IPs are whitelisted.

### System Information

```bash
# Get system status
curl -X GET http://localhost:8080/status

# Get system metrics
curl -X GET http://localhost:8080/metrics

# Response example:
{
  "status": "running",
  "version": "1.0.0",
  "uptime": "2h30m15s",
  "geoip_available": true,
  "temporary_entries": 5
}
```

### IP Management

```bash
# Temporary block IP
curl -X POST http://localhost:8080/temp/block \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "duration": "1h",
    "reason": "Suspicious activity"
  }'

# Temporary allow IP
curl -X POST http://localhost:8080/temp/allow \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.5",
    "duration": "2h",
    "reason": "Maintenance access"
  }'

# List temporary entries
curl -X GET http://localhost:8080/temp/list

# Remove temporary entry
curl -X POST http://localhost:8080/temp/remove \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'
```

### Port Management

```bash
# Get port configuration
curl -X GET http://localhost:8080/ports/list

# Add TCP input ports
curl -X POST http://localhost:8080/ports/tcp/in \
  -H "Content-Type: application/json" \
  -d '{
    "ports": [8080, 9000],
    "ranges": ["8000:8010"],
    "permanent": true
  }'

# Remove UDP input ports
curl -X DELETE http://localhost:8080/ports/udp/in \
  -H "Content-Type: application/json" \
  -d '{
    "ports": [161, 162],
    "permanent": true
  }'

# Get specific port configuration
curl -X GET http://localhost:8080/ports/tcp/in
```

### Geographic Filtering

```bash
# Block country
curl -X POST http://localhost:8080/geo/block \
  -H "Content-Type: application/json" \
  -d '{"country": "CN"}'

# Allow country
curl -X POST http://localhost:8080/geo/allow \
  -H "Content-Type: application/json" \
  -d '{"country": "US"}'

# Add country port whitelist
curl -X POST http://localhost:8080/geo/ports \
  -H "Content-Type: application/json" \
  -d '{
    "country": "US",
    "protocol": "tcp",
    "ports": "22,80,443"
  }'

# Get geographic statistics
curl -X GET http://localhost:8080/geo/stats
```

### Rate Limiting

```bash
# Get rate limiting statistics
curl -X GET http://localhost:8080/ratelimit/stats

# Get rate limiting configuration
curl -X GET http://localhost:8080/ratelimit/config

# Response example:
{
  "enabled": true,
  "global_conn_limit": 100,
  "global_conn_window": "1m",
  "port_specific_limits": "22:5/1m:tcp,80:50/1m:tcp",
  "connection_stats": {
    "tracked_ips": 45,
    "total_entries": 230
  }
}
```

### SYN Flood Protection

```bash
# Get SYN flood statistics
curl -X GET http://localhost:8080/synflood/stats

# Enable SYN flood protection
curl -X POST http://localhost:8080/synflood/enable

# Disable SYN flood protection
curl -X POST http://localhost:8080/synflood/disable

# Get SYN flood configuration
curl -X GET http://localhost:8080/synflood/config
```

### Security Filtering

```bash
# Enable BOGON filtering
curl -X POST http://localhost:8080/security/bogon/enable

# Enable Martian filtering
curl -X POST http://localhost:8080/security/martian/enable

# Get security statistics
curl -X GET http://localhost:8080/security/stats
```

### Dynamic DNS

```bash
# Get DynDNS status
curl -X GET http://localhost:8080/dyndns/status

# Add hostname to monitoring
curl -X POST http://localhost:8080/dyndns/add \
  -H "Content-Type: application/json" \
  -d '{"hostname": "home.example.com"}'

# Force DynDNS update
curl -X POST http://localhost:8080/dyndns/update

# Remove hostname
curl -X DELETE http://localhost:8080/dyndns/remove \
  -H "Content-Type: application/json" \
  -d '{"hostname": "home.example.com"}'
```

### Resource Monitoring

```bash
# Get resource monitoring status
curl -X GET http://localhost:8080/monitor/resources

# Get active alerts
curl -X GET http://localhost:8080/monitor/alerts

# Get configured thresholds
curl -X GET http://localhost:8080/monitor/thresholds

# Response example:
{
  "active_alerts": [
    {
      "metric": "cpu",
      "current_value": 3.2,
      "exceeded_since": "2024-01-15T10:30:00Z",
      "alert_sent": true,
      "critical_sent": false
    }
  ],
  "alert_count": 1
}
```

### Test Mode

```bash
# Start test mode
curl -X POST http://localhost:8080/testmode/start \
  -H "Content-Type: application/json" \
  -d '{
    "duration": "10m",
    "test_connections": ["8.8.8.8", "1.1.1.1"],
    "test_ports": ["22", "80", "443"],
    "revert_on_failure": true
  }'

# Get test mode status
curl -X GET http://localhost:8080/testmode/status

# Stop test mode
curl -X POST http://localhost:8080/testmode/stop

# Manual revert
curl -X POST http://localhost:8080/testmode/revert
```

### Notifications

```bash
# Send test notification
curl -X POST http://localhost:8080/notifications/test

# Test webhook
curl -X POST http://localhost:8080/notifications/webhook/test \
  -H "Content-Type: application/json" \
  -d '{"url": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"}'

# Get notification configuration
curl -X GET http://localhost:8080/notifications/config
```

### fail2ban Integration

```bash
# Get fail2ban status
curl -X GET http://localhost:8080/fail2ban/status

# Ban IP via fail2ban
curl -X POST http://localhost:8080/fail2ban/ban \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.168.1.100",
    "reason": "Manual ban via API"
  }'

# Unban IP
curl -X POST http://localhost:8080/fail2ban/unban \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.1.100"}'

# Get banned IPs
curl -X GET http://localhost:8080/fail2ban/banned
```

### Bulk Operations

```bash
# Import blocklist
curl -X POST http://localhost:8080/import/blocklist \
  -H "Content-Type: text/plain" \
  --data-binary @blocklist.txt

# Example blocklist.txt:
192.168.1.100
203.0.113.0/24
malicious-server.com
```

## Webhook Integration

QFW supports webhook notifications for real-time alerts and events. Webhooks are sent as HTTP POST requests with JSON payloads.

### Webhook Configuration

Configure webhooks in `/etc/qfw/qfw.conf`:

```ini
[notification]
enable_webhooks=true
webhook_urls=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK,https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK
webhook_timeout=10
alert_threshold=1
```

### Webhook Payload Format

All webhooks use a consistent JSON format:

```json
{
  "type": "security_alert",
  "timestamp": "2024-01-15T10:30:00Z",
  "severity": "warning",
  "source": "192.168.1.100",
  "message": "High CPU load detected: 3.2 (threshold: 2.0)",
  "metadata": {
    "metric": "cpu",
    "current_value": 3.2,
    "threshold": 2.0,
    "description": "CPU load average"
  }
}
```

### Event Types

QFW sends webhooks for various events:

#### Security Events
```json
{
  "type": "ip_blocked",
  "severity": "warning",
  "source": "192.168.1.100",
  "message": "IP temporarily blocked for suspicious activity",
  "metadata": {
    "duration": "1h",
    "reason": "brute_force_attempt",
    "block_count": 15
  }
}
```

#### Resource Alerts
```json
{
  "type": "resource_alert",
  "severity": "critical",
  "source": "system",
  "message": "Memory usage is 95.2% (threshold: 80.0%)",
  "metadata": {
    "metric": "memory",
    "current_value": 95.2,
    "threshold": 80.0,
    "duration_exceeded": "5m30s"
  }
}
```

#### SYN Flood Alerts
```json
{
  "type": "syn_flood_alert",
  "severity": "critical",
  "source": "203.0.113.100",
  "message": "SYN flood attack detected from 203.0.113.100",
  "metadata": {
    "syn_rate": 150,
    "threshold": 10,
    "packets_dropped": 1200
  }
}
```

#### Test Mode Events
```json
{
  "type": "test_mode_start",
  "severity": "info",
  "source": "system",
  "message": "QFW test mode started for 5m",
  "metadata": {
    "duration": "5m",
    "revert_enabled": true,
    "test_connections": ["8.8.8.8", "1.1.1.1"],
    "backup_created": true
  }
}
```

#### DynDNS Updates
```json
{
  "type": "dyndns_update",
  "severity": "info",
  "source": "home.example.com",
  "message": "DynDNS hostname home.example.com IP updated",
  "metadata": {
    "hostname": "home.example.com",
    "old_ips": ["203.0.113.10"],
    "new_ips": ["203.0.113.20"]
  }
}
```

### Platform-Specific Examples

#### Slack Integration

1. Create a Slack app and get webhook URL
2. Configure in QFW:
```ini
webhook_urls=https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
```

3. QFW will send formatted messages to Slack:
```
🚨 QFW Alert - Critical
Memory usage is 95.2% (threshold: 80.0%)
Source: system
Time: 2024-01-15 10:30:00 UTC
Metric: memory
Current: 95.2%
Threshold: 80.0%
```

#### Discord Integration

1. Create a Discord webhook in your server
2. Configure in QFW:
```ini
webhook_urls=https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz
```

#### Microsoft Teams

1. Create an incoming webhook connector
2. Configure in QFW:
```ini
webhook_urls=https://yourcompany.webhook.office.com/webhookb2/...
```

#### Custom Applications

Receive webhooks in your application:

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/qfw-webhook', methods=['POST'])
def handle_qfw_webhook():
    data = request.json
    
    # Process QFW event
    event_type = data.get('type')
    severity = data.get('severity')
    message = data.get('message')
    
    if severity == 'critical':
        # Handle critical alerts
        send_sms_alert(message)
    elif event_type == 'ip_blocked':
        # Log security events
        log_security_event(data)
    
    return jsonify({'status': 'received'})
```

### Webhook Testing

Test your webhook configuration:

```bash
# Test all configured webhooks
qfw-cli notify-test

# Test specific webhook URL
qfw-cli webhook-test https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Test via API
curl -X POST http://localhost:8080/notifications/webhook/test \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-webhook-url.com/endpoint"}'
```

### Webhook Security

For production deployments, consider:

1. **HTTPS Only**: Always use HTTPS webhook URLs
2. **Authentication**: Use webhook secrets or API keys
3. **Rate Limiting**: Configure appropriate `webhook_timeout` values
4. **Validation**: Verify webhook payloads in your application
5. **Monitoring**: Monitor webhook delivery success/failures

### Webhook Troubleshooting

Common issues and solutions:

```bash
# Check webhook configuration
qfw-cli status | grep -i webhook

# View webhook logs
journalctl -u qfw | grep webhook

# Test webhook connectivity
curl -X POST https://your-webhook-url.com/endpoint \
  -H "Content-Type: application/json" \
  -d '{"test": "message"}'

# Monitor webhook delivery
qfw-monitor monitor  # Real-time monitoring includes webhook status
```

---

## Additional Resources

- **Documentation**: [Full Documentation](https://github.com/qfiber/qfw/wiki)
- **Examples**: [Configuration Examples](https://github.com/qfiber/qfw/tree/main/examples)
- **API Reference**: [Complete API Documentation](https://github.com/qfiber/qfw/blob/main/docs/api.md)
- **Troubleshooting**: [Common Issues and Solutions](https://github.com/qfiber/qfw/blob/main/docs/troubleshooting.md)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

QFW is released under the GPLv3 License. See [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/qfiber/qfw/issues)
- **Discussions**: [GitHub Discussions](https://github.com/qfiber/qfw/discussions)

## Migration from CSF

QFW provides a seamless migration path from CSF:


## 🚀 Quick Start Examples

### Basic Server Setup

```bash
# 1. Install QFW
git clone https://github.com/yourusername/qfw.git
cd qfw && make install systemd

# 2. Basic configuration
sudo tee /etc/qfw/qfw.conf << EOF
[firewall]
default_policy=drop

[ports]
tcp_in=22,80,443
udp_in=53

[security]
enable_bogon_filter=true
enable_martian_filter=true

[ratelimit]
enable_rate_limit=true
global_conn_limit=100
EOF

# 3. Start QFW
sudo systemctl start qfw
sudo systemctl enable qfw

# 4. Check status
qfw-cli status
```

### Web Server Setup

```bash
# Configure for web server
qfw-cli tcp-in-add "80,443,8080" --permanent
qfw-cli rate-enable
qfw-cli syn-enable

# Add trusted IPs
qfw-cli whitelist 203.0.113.10  # Office IP
qfw-cli temp-allow 198.51.100.5 2h "Client demo"

# Block problematic countries
qfw-cli country-block CN
qfw-cli country-block RU
```

### Development Server Setup

```bash
# More permissive for development
qfw-cli tcp-in-add "3000:4000,8000:9000" --permanent
qfw-cli udp-in-add "5000:6000" --permanent

# Enable test mode for safe changes
qfw-cli test-start 10m
# Make your changes
qfw-cli test-stop  # or wait for auto-revert
```

### High-Security Setup

```bash
# Maximum security configuration
qfw-cli syn-enable
qfw-cli bogon-enable
qfw-cli martian-enable
qfw-cli rate-enable

# Strict rate limiting
sudo sed -i 's/global_conn_limit=100/global_conn_limit=50/' /etc/qfw/qfw.conf
sudo sed -i 's/port_specific_limits=.*/port_specific_limits=22:3\/1m:tcp,80:20\/1m:tcp,443:20\/1m:tcp/' /etc/qfw/qfw.conf

# Block most countries, allow only trusted ones
qfw-cli country-allow US
qfw-cli country-allow CA
qfw-cli country-allow GB

# Enable monitoring with low thresholds
sudo systemctl restart qfw
qfw-monitor setup
```

## Performance Tuning

### For High-Traffic Servers

```ini
[ratelimit]
enable_rate_limit=true
global_conn_limit=1000
port_specific_limits=80:500/1m:tcp,443:500/1m:tcp

[synflood]
enable_protection=true
syn_rate_limit=50
conntrack_max=500

[monitor]
check_interval=10s
cpu_threshold=5.0
memory_threshold=90.0
```

### For Resource-Constrained Systems

```ini
[ratelimit]
enable_rate_limit=true
global_conn_limit=50

[monitor]
check_interval=60s
enable_resource_monitoring=false

[security]
enable_bogon_filter=false  # Reduce memory usage
```


## Monitoring and Observability

### Prometheus Integration

QFW exposes Prometheus metrics on `/metrics` endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'qfw'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard

Import the QFW Grafana dashboard:

```bash
# Download dashboard JSON
wget https://raw.githubusercontent.com/qfiber/qfw/main/monitoring/grafana-dashboard.json

# Import in Grafana UI or via API
curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard.json
```

### Log Analysis

QFW logs are structured for easy analysis:

```bash
# Real-time log monitoring
journalctl -u qfw -f

# JSON log parsing
jq '.level == "warn" or .level == "error"' /var/log/qfw/qfw.log

# Security event analysis
grep "qfw-drop" /var/log/qfw/qfw.log | tail -100
```

## Security Best Practices

1. **Regular Updates**: Keep QFW and dependencies updated
2. **Monitoring**: Enable resource monitoring and alerts
3. **Backup**: Regular configuration backups
4. **Testing**: Use test mode for changes
5. **Logging**: Monitor QFW logs for security events
6. **Fail2ban**: Enable fail2ban integration
7. **GeoIP**: Keep GeoIP database updated
8. **Notifications**: Configure webhook/email alerts


## 📋 Changelog

### v0.0.1 (2025-08-15)
- Initial release
- Complete CSF feature parity
- nftables-based firewall engine
- REST API implementation
- Real-time monitoring
- Test mode with auto-revert
- Webhook notifications
- Code generated by AI (Don't use in production!)

See [CHANGELOG.md](CHANGELOG.md) for complete version history.

## 🙏 Acknowledgments

- **nftables team** for the modern netfilter framework
- **CSF developers** for inspiration and feature reference
- **Go community** for excellent libraries and tools
- **MaxMind** for GeoIP database services
- **fail2ban project** for integration capabilities

---

**Ready to upgrade your firewall?** Start with QFW today and experience next-generation security management!
