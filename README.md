# QFW - qFibre Firewall Manager

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)](https://www.linux.org/)

A comprehensive, high-performance firewall and intrusion prevention system built in Go. QFW provides advanced threat detection, real-time blocking, and intelligent security automation for web servers, hosting providers, and enterprise environments.

## 🚀 Features

### Core Firewall
- **nftables integration** - Modern Linux firewall backend
- **Real-time rule management** - Dynamic IP blocking/whitelisting
- **IPv4/IPv6 support** - Complete dual-stack protection
- **High-performance** - Optimized for high-traffic environments

### Intrusion Prevention System (IPS)
- **Real-time log monitoring** - Continuous security analysis
- **Multi-service protection** - SSH, FTP, SMTP, Web servers
- **Advanced attack detection** - SQL injection, shell uploads, directory traversal
- **Automatic blocking** - Immediate response to threats

### Web Security
- **cPanel/DirectAdmin protection** - Hosting panel security
- **WordPress security** - Brute force and attack prevention
- **Apache/Nginx monitoring** - Web server log analysis
- **404 scan detection** - Automated scanner blocking

### Enhanced GeoIP Protection
- **Per-service country rules** - Different rules for SSH vs web
- **VPN/Proxy detection** - Block anonymizers and bad actors
- **MaxMind integration** - Professional GeoIP database support
- **Intelligent caching** - Performance-optimized lookups

### Advanced Monitoring
- **Port scan detection** - Network reconnaissance prevention
- **File system monitoring** - Critical file change detection
- **Process monitoring** - Suspicious activity identification
- **External threat feeds** - Spamhaus, DShield, Abuse.ch integration

### Automation & Alerts
- **Progressive blocking** - Escalating penalties for repeat offenders
- **Email notifications** - Real-time security alerts
- **Webhook integration** - Custom alert delivery
- **Auto-cleanup** - Temporary blocks with expiration

## 🛠️ Installation

### Prerequisites
- Linux system with nftables support
- Go 1.19 or later
- Root privileges for firewall management

### Build from Source
```bash
git clone https://github.com/qfiber/qfw.git
cd qfw
make build
```

### System Installation
```bash
sudo make install
sudo systemctl enable qfw
sudo systemctl start qfw
```

## ⚙️ Configuration

### Basic Configuration
Create `/etc/qfw/qfw.conf`:

```ini
[firewall]
default_policy=drop
enable_ipv6=false

[ports]
tcp_in=22,80,443
tcp_out=80,443,53
udp_out=53,123

[ips]
enable_ips=true
log_check_interval=30s
temp_block_duration=1h
auto_whitelist_ssh_sessions=true
ssh_whitelist_duration=1h

[geoip]
mmdb_path=/opt/geoip/GeoLite2-Country.mmdb
enable_per_service_rules=true
enable_vpn_detection=true
cache_vpn_results=true

[notification]
enable_email=true
email_server=smtp.example.com
email_port=587
email_user=alerts@example.com
email_password=your_password
email_to=admin@example.com
```

### Advanced Configuration
```ini
# Detection Rules
cpanel_failed_logins=3
cpanel_time_window=5m
wordpress_failed_logins=5
wordpress_time_window=10m

# Log File Paths
apache_log_files=/var/log/apache2/access.log,/var/log/httpd/access_log
nginx_log_files=/var/log/nginx/access.log
cpanel_log_files=/usr/local/cpanel/logs/login_log

# Phase 2 Features
enable_port_scan_detection=true
port_scan_threshold=10
enable_filesystem_monitor=true
enable_process_monitor=true
enable_external_blocklists=true

# VPN Detection
vpn_api_key=your_ipqualityscore_key
cache_expiration=24h
```

## 🎯 Usage

### Command Line Interface
```bash
# Service Management
qfw-cli enable                    # Enable and start service
qfw-cli disable                   # Stop and disable service
qfw-cli status                    # Show firewall status
qfw-cli reload                    # Reload configuration

# IP Management
qfw-cli whitelist add 192.168.1.100
qfw-cli blacklist add 10.0.0.50
qfw-cli whitelist remove 192.168.1.100

# IPS Management
qfw-cli ips status                # Show IPS statistics
qfw-cli ips blocked               # List blocked IPs
qfw-cli ips unblock 1.2.3.4      # Unblock specific IP
qfw-cli ips whitelist-add 5.6.7.8 "Trusted partner"

# Enhanced GeoIP
qfw-cli ips geoip-check 8.8.8.8 ssh    # Check country rules
qfw-cli ips vpn-check 1.2.3.4          # Check VPN status
qfw-cli ips service-rules               # Show service rules

# Monitoring
qfw-cli metrics                   # System metrics
qfw-cli logs 100                  # Show recent logs
```

### REST API
```bash
# Status and Metrics
curl http://localhost:8080/status
curl http://localhost:8080/metrics

# IP Management
curl -X POST "http://localhost:8080/whitelist?ip=192.168.1.100"
curl -X DELETE "http://localhost:8080/blacklist?ip=10.0.0.50"

# IPS Management
curl http://localhost:8080/api/ips/blocked
curl http://localhost:8080/api/ips/stats
curl -X POST "http://localhost:8080/api/ips/unblock?ip=1.2.3.4"

# Enhanced GeoIP
curl "http://localhost:8080/api/geoip/check?ip=8.8.8.8&service=ssh"
curl "http://localhost:8080/api/geoip/vpn-check?ip=1.2.3.4"
```

## 🔧 Development

### Build Options
```bash
make build          # Build binaries
make test           # Run tests
make clean          # Clean build artifacts
make dev            # Development mode
make release        # Multi-platform release builds
```

### Code Quality
```bash
make fmt            # Format code
make vet            # Run go vet
make lint           # Run golangci-lint
make check          # All quality checks
```

## 📊 Monitoring & Metrics

### Prometheus Integration
QFW exposes metrics at `http://localhost:8080/prometheus`:
- `qfw_blocked_ips_total` - Total blocked IPs
- `qfw_attacks_detected_total` - Attacks by type and service
- `qfw_cpu_usage_percent` - System resource usage
- `qfw_log_entries_total` - Log processing statistics

### Performance Metrics
- Real-time log processing (30-second intervals)
- Sub-second blocking response time
- Efficient memory usage with automatic cleanup
- Scalable to high-traffic environments

## 🛡️ Security Features

### Attack Detection
- **Brute Force**: SSH, FTP, cPanel, DirectAdmin, WordPress
- **Web Attacks**: SQL injection, XSS, shell uploads, directory traversal
- **Network Attacks**: Port scanning, SYN floods, connection abuse
- **System Attacks**: Suspicious processes, file modifications

### Threat Intelligence
- **External Feeds**: Spamhaus, DShield, Abuse.ch blocklists
- **GeoIP Blocking**: Country-based restrictions per service
- **VPN Detection**: Comprehensive anonymizer identification
- **Reputation Scoring**: Multi-source threat assessment

### Response Actions
- **Immediate Blocking**: Real-time threat response
- **Progressive Penalties**: Escalating blocks for repeat offenders
- **Temporary Blocks**: Automatic expiration and cleanup
- **Permanent Bans**: Persistent threat blocking

## 🌐 Supported Services

### Web Servers
- Apache HTTP Server
- Nginx
- LiteSpeed
- Custom log formats

### Control Panels
- cPanel/WHM
- DirectAdmin
- Webmin
- Custom panels

### Mail Services
- Postfix
- Dovecot
- Exim
- Custom mail servers

### Additional Services
- SSH/SFTP
- FTP/FTPS
- Custom applications

## 📁 Project Structure

```
qfw/
├── cmd/
│   ├── qfw/              # Main firewall daemon
│   └── qfw-cli/          # Command line interface
├── internal/
│   ├── api/              # REST API server
│   ├── config/           # Configuration management
│   ├── firewall/         # nftables integration
│   ├── geoip/            # GeoIP and VPN detection
│   ├── ips/              # Intrusion prevention system
│   ├── logger/           # Structured logging
│   ├── monitor/          # System monitoring
│   └── notify/           # Alert notifications
├── configs/              # Example configurations
├── systemd/              # Systemd service files
└── docs/                 # Documentation
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Reporting Issues
Please use GitHub Issues to report bugs or request features. Include:
- Operating system and version
- QFW version
- Configuration details
- Log excerpts (sanitized)

## 📋 Requirements

### System Requirements
- Linux kernel 3.13+ with nftables support
- 512MB RAM minimum (1GB recommended)
- 100MB disk space
- Network interface access

### Dependencies
- nftables
- systemd (for service management)
- GeoIP database (optional but recommended)

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **MaxMind** for GeoIP database services
- **Spamhaus** for threat intelligence feeds
- **nftables project** for the firewall framework
- **Go community** for excellent libraries

## 📞 Support

- **Documentation**: [Wiki](https://github.com/qfiber/qfw/wiki)
- **Issues**: [GitHub Issues](https://github.com/qfiber/qfw/issues)
- **Discussions**: [GitHub Discussions](https://github.com/qfiber/qfw/discussions)

---

**QFW** - Enterprise-grade security for the modern web. Built with Go, powered by intelligence.
=======
Modern CSF replacement built with Go and nftables, featuring REST API, live metrics, and comprehensive security filtering.

## Features

- **nftables-based architecture** - Modern netfilter backend
- **REST API** - Full automation support
- **Live metrics & alerts** - Prometheus integration
- **Advanced filtering** - SYN flood, rate limits, BOGON/Martian filtering
- **GeoIP blocking** - Country-based access control
- **Multiple notifications** - Email, webhooks (Slack, Discord, n8n)
- **Test mode** - Safe configuration testing with auto-revert
- **O(1) IP lookups** - Efficient nftables sets

## Quick Start

```bash
# Build and install
make install

# Enable and start service
qfw-cli enable

# Check status
qfw-cli status

# View metrics
qfw-cli metrics

# Add IP to whitelist
qfw-cli whitelist add 192.168.1.100

# View logs
qfw-cli logs 100
```

## Configuration

Edit `/etc/qfw/qfw.conf` with your settings. See example configuration for all options.

## API Usage

```bash
# Get status
curl http://localhost:8080/status

# Add IP to blacklist
curl -X POST "http://localhost:8080/blacklist?ip=1.2.3.4"

# Reload configuration
curl -X POST http://localhost:8080/reload

# Prometheus metrics
curl http://localhost:8080/prometheus
```

## Requirements

- Linux with nftables support
- Go 1.21+ (for building)
- Root privileges (for nftables management)
>>>>>>> b95c977 (Initial commit)
