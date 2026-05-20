package wailsapp

import (
	"context"
	"fmt"
	"portdesk/internal/scanner"
	"portdesk/internal/webcheck"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx         context.Context
	scanCancel  context.CancelFunc
	checkCancel context.CancelFunc
	mu          sync.Mutex
	running     bool
}

type WebCheckResult struct {
	CheckedAt            string         `json:"checkedAt"`
	Target               string         `json:"target"`
	FinalURL             string         `json:"finalUrl"`
	StatusCode           int            `json:"statusCode"`
	UsesHTTPS            bool           `json:"usesHttps"`
	TLSVersion           string         `json:"tlsVersion"`
	HTTPRedirectsToHTTPS bool           `json:"httpRedirectsToHttps"`
	SupportedMethods     []string       `json:"supportedMethods"`
	CheckedModules       []string       `json:"checkedModules"`
	DVWACoverage         []CoverageItem `json:"dvwaCoverage"`
	Findings             []Finding      `json:"findings"`
}

type Finding struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Title          string `json:"title"`
	Details        string `json:"details"`
	Recommendation string `json:"recommendation"`
	Evidence       string `json:"evidence"`
}

type CoverageItem struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Notes  string `json:"notes"`
}

type PortScanResult struct {
	OpenPorts []OpenPortItem `json:"openPorts"`
	Total     int            `json:"total"`
	Scanned   int            `json:"scanned"`
	Host      string         `json:"host"`
}

type OpenPortItem struct {
	Port       int    `json:"port"`
	DurationMs int    `json:"durationMs"`
	Service    string `json:"service"`
}

type PortScanProgress struct {
	CheckedPort  int `json:"checkedPort"`
	CheckedCount int `json:"checkedCount"`
	Total        int `json:"total"`
	OpenPort     int `json:"openPort"`
}

func NewApp() *App {
	return &App{}
}

func (a *App) Startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) Shutdown(ctx context.Context) {
}

func (a *App) GetAppName() string {
	return "PortDesk"
}

func (a *App) IsRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

func (a *App) StopTask() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.scanCancel != nil {
		a.scanCancel()
	}
	if a.checkCancel != nil {
		a.checkCancel()
	}
	a.running = false
}

func (a *App) RunWebCheck(target string) (*WebCheckResult, error) {
	if target == "" {
		return nil, fmt.Errorf("目标网址不能为空")
	}

	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil, fmt.Errorf("当前已有任务在执行中")
	}

	checkCtx, cancel := context.WithCancel(a.ctx)
	a.checkCancel = cancel
	a.running = true
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.running = false
		a.checkCancel = nil
		a.mu.Unlock()
	}()

	report, err := webcheck.Check(checkCtx, target)
	if err != nil {
		if checkCtx.Err() != nil {
			return nil, fmt.Errorf("检测已停止")
		}
		return nil, err
	}

	return toWebCheckResult(report), nil
}

func (a *App) RunPortScan(host string, startPort int, endPort int, workers int, timeoutMs int, ipVersion string) (*PortScanResult, error) {
	if host == "" || startPort <= 0 || endPort <= 0 {
		return nil, fmt.Errorf("参数不正确")
	}

	if workers <= 0 {
		workers = 100
	}
	if timeoutMs <= 0 {
		timeoutMs = 2000
	}

	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return nil, fmt.Errorf("当前已有任务在执行中")
	}

	scanCtx, cancel := context.WithCancel(a.ctx)
	a.scanCancel = cancel
	a.running = true
	a.mu.Unlock()

	defer func() {
		a.mu.Lock()
		a.running = false
		a.scanCancel = nil
		a.mu.Unlock()
	}()

	opts := scanner.ScanOptions{
		Host:      host,
		StartPort: startPort,
		EndPort:   endPort,
		Workers:   workers,
		Timeout:   time.Duration(timeoutMs) * time.Millisecond,
		IPVersion: scanner.IPVersion(ipVersion),
	}

	progressHandler := func(p scanner.Progress) {
		openPort := 0
		if p.Open != nil {
			openPort = p.Open.Port
		}
		runtime.EventsEmit(a.ctx, "portscan:progress", PortScanProgress{
			CheckedPort:  p.CheckedPort,
			CheckedCount: p.CheckedCount,
			Total:        p.Total,
			OpenPort:     openPort,
		})
	}

	openPorts, err := scanner.Scan(scanCtx, opts, progressHandler)

	result := &PortScanResult{
		Host:    host,
		Total:   endPort - startPort + 1,
		Scanned: len(openPorts),
	}

	for _, p := range openPorts {
		result.OpenPorts = append(result.OpenPorts, OpenPortItem{
			Port:       p.Port,
			DurationMs: int(p.Duration.Milliseconds()),
			Service:    guessService(p.Port),
		})
	}

	if err != nil && scanCtx.Err() == nil {
		return result, err
	}

	return result, nil
}

func toWebCheckResult(report webcheck.Report) *WebCheckResult {
	findings := make([]Finding, 0, len(report.Findings))
	for _, f := range report.Findings {
		findings = append(findings, Finding{
			Severity:       string(f.Severity),
			Category:       f.Category,
			Title:          f.Title,
			Details:        f.Details,
			Recommendation: f.Recommendation,
			Evidence:       f.Evidence,
		})
	}

	coverage := make([]CoverageItem, 0, len(report.DVWACoverage))
	for _, c := range report.DVWACoverage {
		coverage = append(coverage, CoverageItem{
			Name:   c.Name,
			Status: c.Status,
			Notes:  c.Notes,
		})
	}

	return &WebCheckResult{
		CheckedAt:            report.CheckedAt.Format("2006-01-02 15:04:05"),
		Target:               report.Target,
		FinalURL:             report.FinalURL,
		StatusCode:           report.StatusCode,
		UsesHTTPS:            report.UsesHTTPS,
		TLSVersion:           report.TLSVersion,
		HTTPRedirectsToHTTPS: report.HTTPRedirectsToHTTPS,
		SupportedMethods:     report.SupportedMethods,
		CheckedModules:       report.CheckedModules,
		DVWACoverage:         coverage,
		Findings:             findings,
	}
}

func guessService(port int) string {
	services := map[int]string{
		20:    "FTP-Data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		993:   "IMAPS",
		995:   "POP3S",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		8080:  "HTTP-Proxy",
		8443:  "HTTPS-Alt",
		27017: "MongoDB",
	}

	if svc, ok := services[port]; ok {
		return svc
	}

	if port >= 8000 && port <= 8999 {
		return "HTTP-Alt"
	}

	return fmt.Sprintf("Unknown:%d", port)
}
