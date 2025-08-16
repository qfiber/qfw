// internal/monitor/monitor.go
package monitor

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"

	"qfw/internal/config"
	"qfw/internal/logger"
	"qfw/internal/notify"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	defaultCollectionInterval = 30 * time.Second
	defaultAlertCooldown      = 10 * time.Minute
)

type SystemMonitor struct {
	config        *config.MonitorConfig
	notifier      *notify.Notifier
	metrics       *MonitorMetrics
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	alertCooldown *sync.Map // thread-safe cooldown tracking
}

type MonitorMetrics struct {
	cpuUsage    prometheus.Gauge
	memoryUsage prometheus.Gauge
	diskUsage   prometheus.Gauge
	connections prometheus.Gauge
}

func NewSystemMonitor(cfg *config.MonitorConfig, notifier *notify.Notifier) (*SystemMonitor, error) {
	if cfg == nil {
		return nil, ErrNilConfig
	}
	if notifier == nil {
		return nil, ErrNilNotifier
	}

	metrics := &MonitorMetrics{
		cpuUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qfw_cpu_usage_percent",
			Help: "Current CPU usage percentage",
		}),
		memoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qfw_memory_usage_percent",
			Help: "Current memory usage percentage",
		}),
		diskUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qfw_disk_usage_percent",
			Help: "Current disk usage percentage",
		}),
		connections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "qfw_active_connections",
			Help: "Number of active connections",
		}),
	}

	if err := prometheus.Register(metrics.cpuUsage); err != nil {
		return nil, err
	}
	if err := prometheus.Register(metrics.memoryUsage); err != nil {
		return nil, err
	}
	if err := prometheus.Register(metrics.diskUsage); err != nil {
		return nil, err
	}
	if err := prometheus.Register(metrics.connections); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &SystemMonitor{
		config:        cfg,
		notifier:      notifier,
		metrics:       metrics,
		ctx:           ctx,
		cancel:        cancel,
		alertCooldown: &sync.Map{},
	}, nil
}

func (m *SystemMonitor) Start() {
	if !m.config.EnableResourceMonitoring {
		logger.Debug("monitor", "Resource monitoring disabled in config")
		return
	}

	interval := defaultCollectionInterval

	logger.Info("monitor", "Starting system monitor", "interval", interval)

	m.wg.Add(1)
	go m.runMonitoringLoop(interval)
}

func (m *SystemMonitor) runMonitoringLoop(interval time.Duration) {
	defer m.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collectAndAlert()
		case <-m.ctx.Done():
			logger.Info("monitor", "Stopping monitoring loop")
			return
		}
	}
}

func (m *SystemMonitor) collectAndAlert() {
	var wg sync.WaitGroup

	if m.config.CPUAlert {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.checkCPUUsage()
		}()
	}

	if m.config.MemoryAlert {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.checkMemoryUsage()
		}()
	}

	if m.config.DiskAlert {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.checkDiskUsage()
		}()
	}

	wg.Wait()
}

func (m *SystemMonitor) checkCPUUsage() {
	cpuUsage, err := m.getCPUUsage()
	if err != nil {
		logger.Error("monitor", "Failed to get CPU usage", "error", err)
		return
	}

	m.metrics.cpuUsage.Set(cpuUsage)

	if cpuUsage > m.config.CPUThreshold && m.shouldAlert("cpu") {
		m.notifier.SendAlert("High CPU Usage", map[string]interface{}{
			"cpu_usage": cpuUsage,
			"threshold": m.config.CPUThreshold,
		})
		m.alertCooldown.Store("cpu", time.Now())
	}
}

func (m *SystemMonitor) checkMemoryUsage() {
	memUsage, err := m.getMemoryUsage()
	if err != nil {
		logger.Error("monitor", "Failed to get memory usage", "error", err)
		return
	}

	m.metrics.memoryUsage.Set(memUsage)

	if memUsage > m.config.MemoryThreshold && m.shouldAlert("memory") {
		m.notifier.SendAlert("High Memory Usage", map[string]interface{}{
			"memory_usage": memUsage,
			"threshold":    m.config.MemoryThreshold,
		})
		m.alertCooldown.Store("memory", time.Now())
	}
}

func (m *SystemMonitor) checkDiskUsage() {
	diskUsage, err := m.getDiskUsage()
	if err != nil {
		logger.Error("monitor", "Failed to get disk usage", "error", err)
		return
	}

	m.metrics.diskUsage.Set(diskUsage)

	if diskUsage > m.config.DiskThreshold && m.shouldAlert("disk") {
		m.notifier.SendAlert("High Disk Usage", map[string]interface{}{
			"disk_usage": diskUsage,
			"threshold":  m.config.DiskThreshold,
		})
		m.alertCooldown.Store("disk", time.Now())
	}
}

func (m *SystemMonitor) shouldAlert(alertType string) bool {
	lastAlert, exists := m.alertCooldown.Load(alertType)
	if !exists {
		return true
	}

	return time.Since(lastAlert.(time.Time)) > defaultAlertCooldown
}

func (m *SystemMonitor) getCPUUsage() (float64, error) {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return 0, err
	}

	userTime := float64(rusage.Utime.Sec) + float64(rusage.Utime.Usec)/1e6
	sysTime := float64(rusage.Stime.Sec) + float64(rusage.Stime.Usec)/1e6

	// Calculate percentage of CPU used in the last interval
	return (userTime + sysTime) * 100 / defaultCollectionInterval.Seconds(), nil
}

func (m *SystemMonitor) getMemoryUsage() (float64, error) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	var sysinfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&sysinfo); err != nil {
		return 0, err
	}

	totalMem := float64(sysinfo.Totalram)
	usedMem := float64(memStats.Sys)

	if totalMem == 0 {
		return 0, ErrZeroTotalMemory
	}

	return (usedMem / totalMem) * 100, nil
}

func (m *SystemMonitor) getDiskUsage() (float64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0, err
	}

	total := float64(stat.Blocks * uint64(stat.Bsize))
	free := float64(stat.Bavail * uint64(stat.Bsize))

	if total == 0 {
		return 0, ErrZeroTotalDisk
	}

	return ((total - free) / total) * 100, nil
}

func (m *SystemMonitor) Stop() {
	m.cancel()
	m.wg.Wait()
	logger.Info("monitor", "System monitor stopped")
}

func (m *SystemMonitor) GetMetrics() (map[string]float64, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	metrics := make(map[string]float64)
	var errs []error

	collect := func(name string, fn func() (float64, error)) {
		defer wg.Done()
		value, err := fn()
		if err != nil {
			mu.Lock()
			errs = append(errs, err)
			mu.Unlock()
			return
		}
		mu.Lock()
		metrics[name] = value
		mu.Unlock()
	}

	wg.Add(3)
	go collect("cpu_usage", m.getCPUUsage)
	go collect("memory_usage", m.getMemoryUsage)
	go collect("disk_usage", m.getDiskUsage)
	wg.Wait()

	if len(errs) > 0 {
		return metrics, ErrPartialMetrics{Errors: errs}
	}

	return metrics, nil
}

// Custom errors for better error handling
var (
	ErrNilConfig       = errors.New("monitor config cannot be nil")
	ErrNilNotifier     = errors.New("notifier cannot be nil")
	ErrZeroTotalMemory = errors.New("total memory reported as zero")
	ErrZeroTotalDisk   = errors.New("total disk space reported as zero")
)

type ErrPartialMetrics struct {
	Errors []error
}

func (e ErrPartialMetrics) Error() string {
	return fmt.Sprintf("partial metrics collected with %d errors", len(e.Errors))
}
