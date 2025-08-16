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
				Name: "qfw_log_entries_total",
				Help: "Total number of log entries by level",
			},
			[]string{"level", "component"},
		),
	}

	prometheus.MustRegister(promLogger.logCounter)

	return &Logger{
		slog:       slog.New(slog.NewJSONHandler(os.Stdout, nil)),
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

	// JSON output for journalctl
	jsonData, _ := json.Marshal(entry)
	fmt.Println(string(jsonData))

	// Prometheus metrics
	l.prometheus.logCounter.WithLabelValues(level, component).Inc()

	// Standard slog
	switch level {
	case "INFO":
		l.slog.Info(msg, "component", component)
	case "ERROR":
		l.slog.Error(msg, "component", component)
	case "DEBUG":
		l.slog.Debug(msg, "component", component)
	case "WARN":
		l.slog.Warn(msg, "component", component)
	}
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
