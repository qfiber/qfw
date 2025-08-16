// internal/logger/logger.go
package logger

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Logger struct {
	slog       *slog.Logger
	prometheus *PrometheusLogger
}

type PrometheusLogger struct {
	logCounter *prometheus.CounterVec
}

type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Component string                 `json:"component"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

var DefaultLogger *Logger

func init() {
	DefaultLogger = New()
}

func New() *Logger {
	promLogger := &PrometheusLogger{
		logCounter: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "qff_log_entries_total",
				Help: "Total number of log entries by level",
			},
			[]string{"level", "component"},
		),
	}

	prometheus.MustRegister(promLogger.logCounter)

	// Configure slog for journald with proper identifier
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}

	return &Logger{
		slog:       slog.New(slog.NewJSONHandler(os.Stdout, opts)),
		prometheus: promLogger,
	}
}

func (l *Logger) Info(component, msg string, fields ...interface{}) {
	l.log("INFO", component, msg, fields...)
}

func (l *Logger) Error(component, msg string, fields ...interface{}) {
	l.log("ERROR", component, msg, fields...)
}

func (l *Logger) Debug(component, msg string, fields ...interface{}) {
	l.log("DEBUG", component, msg, fields...)
}

func (l *Logger) Warn(component, msg string, fields ...interface{}) {
	l.log("WARN", component, msg, fields...)
}

// Add firewall-specific logging methods
func (l *Logger) LogFirewallBlock(action, direction, protocol string, port int, srcIP, dstIP string) {
	l.Info("firewall", fmt.Sprintf("FIREWALL %s %s", action, direction),
		"action", action,
		"direction", direction,
		"protocol", protocol,
		"port", port,
		"src_ip", srcIP,
		"dst_ip", dstIP,
		"rule_type", "port_rule")
}

func (l *Logger) LogIPBlock(action, reason string, ip string) {
	l.Info("firewall", fmt.Sprintf("IP %s: %s", action, ip),
		"action", action,
		"ip", ip,
		"reason", reason,
		"rule_type", "ip_rule")
}

func (l *Logger) log(level, component, msg string, fields ...interface{}) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   msg,
		Component: component,
	}

	if len(fields) > 0 {
		entry.Fields = make(map[string]interface{})
		for i := 0; i < len(fields)-1; i += 2 {
			if key, ok := fields[i].(string); ok {
				entry.Fields[key] = fields[i+1]
			}
		}
	}

	// Format for journald with qFiber Firewall identifier
	fmt.Printf("qFiber Firewall[%d]: %s [%s] %s\n",
		os.Getpid(), level, component, msg)

	// Also output structured JSON for parsing
	if len(fields) > 0 {
		jsonData, _ := json.Marshal(entry.Fields)
		fmt.Printf("qFiber Firewall[%d]: STRUCTURED: %s\n",
			os.Getpid(), string(jsonData))
	}

	// Prometheus metrics
	l.prometheus.logCounter.WithLabelValues(level, component).Inc()
}

func Info(component, msg string, fields ...interface{}) {
	DefaultLogger.Info(component, msg, fields...)
}

func Error(component, msg string, fields ...interface{}) {
	DefaultLogger.Error(component, msg, fields...)
}

func Debug(component, msg string, fields ...interface{}) {
	DefaultLogger.Debug(component, msg, fields...)
}

func Warn(component, msg string, fields ...interface{}) {
	DefaultLogger.Warn(component, msg, fields...)
}

// Firewall-specific logging functions
func LogFirewallBlock(action, direction, protocol string, port int, srcIP, dstIP string) {
	DefaultLogger.LogFirewallBlock(action, direction, protocol, port, srcIP, dstIP)
}

func LogIPBlock(action, reason string, ip string) {
	DefaultLogger.LogIPBlock(action, reason, ip)
}
