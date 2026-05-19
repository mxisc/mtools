package webcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Severity string

const (
	SeverityInfo   Severity = "信息"
	SeverityLow    Severity = "低"
	SeverityMedium Severity = "中"
	SeverityHigh   Severity = "高"
)

type Finding struct {
	Severity       Severity
	Category       string
	Title          string
	Details        string
	Recommendation string
	Evidence       string
}

type CoverageItem struct {
	Name   string
	Status string
	Notes  string
}

type Report struct {
	CheckedAt            time.Time
	Target               string
	FinalURL             string
	StatusCode           int
	UsesHTTPS            bool
	TLSVersion           string
	HTTPRedirectsToHTTPS bool
	SupportedMethods     []string
	CheckedModules       []string
	DVWACoverage         []CoverageItem
	Findings             []Finding
}

func Check(ctx context.Context, rawTarget string) (Report, error) {
	targetURL, err := normalizeURL(rawTarget)
	if err != nil {
		return Report{}, err
	}

	client := newHTTPClient(true)
	baseSnapshot, err := performRequest(ctx, client, http.MethodGet, targetURL, nil)
	if err != nil {
		return Report{}, fmt.Errorf("请求失败: %w", err)
	}

	finalURL := baseSnapshot.URL
	report := Report{
		CheckedAt:  time.Now(),
		Target:     targetURL,
		FinalURL:   finalURL,
		StatusCode: baseSnapshot.StatusCode,
		UsesHTTPS:  strings.HasPrefix(finalURL, "https://"),
		TLSVersion: tlsVersion(baseSnapshot.TLS),
		CheckedModules: []string{
			"传输层",
			"安全响应头",
			"Cookie",
			"CORS",
			"HTTP 方法",
			"页面与前端面",
			"身份与权限面",
			"接口与业务面",
			"公开文件",
			"敏感暴露",
			"主动探针",
			"基础设施与供应链",
			"DVWA 类目覆盖",
		},
		Findings: make([]Finding, 0),
	}

	surface := analyzeHTMLSurface(finalURL, baseSnapshot.BodySnippet)

	httpRedirects, redirectTarget, redirectErr := probeHTTPRedirect(ctx, targetURL)
	if redirectErr == nil {
		report.HTTPRedirectsToHTTPS = httpRedirects
		if report.UsesHTTPS && !httpRedirects {
			addFinding(&report, SeverityMedium, "传输层", "HTTP 未强制跳转到 HTTPS", "通过 HTTP 访问时没有可靠地跳转到 HTTPS。", "为 80 端口配置 301/308 跳转到 HTTPS。", redirectTarget)
		}
	}

	collectTransportFindings(&report, baseSnapshot)
	collectHeaderFindings(&report, baseSnapshot)
	collectCookieFindings(&report, baseSnapshot)
	collectCORSFindings(ctx, &report, finalURL)
	collectMethodFindings(ctx, &report, finalURL)
	collectDiscoveryFindings(ctx, &report, finalURL)
	collectSensitiveExposureFindings(ctx, &report, finalURL)
	collectExposureFindings(&report, baseSnapshot)
	collectAppSurfaceFindings(&report, surface, baseSnapshot)
	collectIdentityFindings(&report, surface, baseSnapshot)
	collectBusinessLogicFindings(&report, surface)
	collectReflectionFindings(ctx, &report, finalURL, surface)
	collectOpenRedirectValidationFindings(ctx, &report, finalURL, surface)
	collectInfraSupplyChainFindings(&report, finalURL, surface)
	report.DVWACoverage = buildDVWACoverage(surface, report)

	if len(report.Findings) == 0 {
		addFinding(&report, SeverityInfo, "概览", "未发现明显配置问题", "本次检测未发现明显的基础配置风险，但这不代表站点不存在其他安全问题。", "继续结合 SAST/DAST、依赖审计和人工测试做更完整验证。", "")
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		return severityRank(report.Findings[i].Severity) > severityRank(report.Findings[j].Severity)
	})

	return report, nil
}

func normalizeURL(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("目标网址不能为空")
	}

	if !strings.Contains(value, "://") {
		value = "https://" + value
	}

	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return "", fmt.Errorf("网址格式不正确: %w", err)
	}

	if parsed.Host == "" {
		return "", fmt.Errorf("网址必须包含主机名")
	}

	if parsed.Path == "" {
		parsed.Path = "/"
	}

	return parsed.String(), nil
}

func collectTransportFindings(report *Report, snapshot responseSnapshot) {
	if !report.UsesHTTPS {
		addFinding(report, SeverityHigh, "传输层", "未使用 HTTPS", "最终访问地址未启用 HTTPS，通信内容可能被窃听或篡改。", "为站点启用 HTTPS，并将 HTTP 请求重定向到 HTTPS。", report.FinalURL)
		return
	}

	if snapshot.TLS == nil {
		return
	}

	if snapshot.TLS.Version < tls.VersionTLS12 {
		addFinding(report, SeverityHigh, "传输层", "TLS 版本过低", fmt.Sprintf("检测到 TLS 版本为 %s。", tlsVersion(snapshot.TLS)), "至少启用 TLS 1.2，推荐 TLS 1.3。", "")
	}

	if len(snapshot.TLS.CipherSuiteName) > 0 && strings.Contains(strings.ToUpper(snapshot.TLS.CipherSuiteName), "RC4") {
		addFinding(report, SeverityHigh, "传输层", "使用弱加密套件", fmt.Sprintf("检测到弱加密套件 %s。", snapshot.TLS.CipherSuiteName), "禁用弱加密套件，仅保留现代安全套件。", "")
	}
}

func collectHeaderFindings(report *Report, snapshot responseSnapshot) {
	headers := snapshot.Headers

	requiredHeaders := []struct {
		name           string
		severity       Severity
		title          string
		recommendation string
		httpsOnly      bool
	}{
		{
			name:           "Content-Security-Policy",
			severity:       SeverityMedium,
			title:          "缺少 Content-Security-Policy",
			recommendation: "配置 CSP，限制脚本、样式、图片和第三方资源来源。",
		},
		{
			name:           "X-Frame-Options",
			severity:       SeverityMedium,
			title:          "缺少 X-Frame-Options",
			recommendation: "配置 DENY 或 SAMEORIGIN，降低点击劫持风险。",
		},
		{
			name:           "X-Content-Type-Options",
			severity:       SeverityMedium,
			title:          "缺少 X-Content-Type-Options",
			recommendation: "设置为 nosniff，避免浏览器 MIME 嗅探。",
		},
		{
			name:           "Referrer-Policy",
			severity:       SeverityLow,
			title:          "缺少 Referrer-Policy",
			recommendation: "设置合理的 Referrer-Policy，减少来源信息泄露。",
		},
		{
			name:           "Permissions-Policy",
			severity:       SeverityLow,
			title:          "缺少 Permissions-Policy",
			recommendation: "显式限制浏览器权限能力，例如 camera、microphone、geolocation。",
		},
		{
			name:           "Strict-Transport-Security",
			severity:       SeverityMedium,
			title:          "缺少 HSTS",
			recommendation: "在 HTTPS 站点上启用 Strict-Transport-Security。",
			httpsOnly:      true,
		},
		{
			name:           "Cross-Origin-Opener-Policy",
			severity:       SeverityLow,
			title:          "缺少 Cross-Origin-Opener-Policy",
			recommendation: "为需要隔离上下文的页面增加 COOP，例如 same-origin。",
		},
		{
			name:           "Cross-Origin-Resource-Policy",
			severity:       SeverityLow,
			title:          "缺少 Cross-Origin-Resource-Policy",
			recommendation: "按资源类型增加 CORP，减少跨站资源滥用面。",
		},
		{
			name:           "Cross-Origin-Embedder-Policy",
			severity:       SeverityLow,
			title:          "缺少 Cross-Origin-Embedder-Policy",
			recommendation: "为需要跨源隔离的应用增加 COEP。",
		},
		{
			name:           "X-Permitted-Cross-Domain-Policies",
			severity:       SeverityLow,
			title:          "缺少 X-Permitted-Cross-Domain-Policies",
			recommendation: "设置为 none，减少旧式跨域策略文件被滥用。",
		},
	}

	for _, item := range requiredHeaders {
		if item.httpsOnly && !report.UsesHTTPS {
			continue
		}
		if headers.Get(item.name) == "" {
			addFinding(report, item.severity, "安全响应头", item.title, fmt.Sprintf("响应头中未找到 %s。", item.name), item.recommendation, "")
		}
	}

	csp := headers.Get("Content-Security-Policy")
	if csp != "" {
		lowerCSP := strings.ToLower(csp)
		if strings.Contains(lowerCSP, "unsafe-inline") {
			addFinding(report, SeverityMedium, "安全响应头", "CSP 允许 unsafe-inline", "当前 Content-Security-Policy 包含 unsafe-inline。", "尽量移除 unsafe-inline，改用 nonce 或 hash。", csp)
		}
		if strings.Contains(lowerCSP, "unsafe-eval") {
			addFinding(report, SeverityMedium, "安全响应头", "CSP 允许 unsafe-eval", "当前 Content-Security-Policy 包含 unsafe-eval。", "移除 unsafe-eval，避免动态执行脚本。", csp)
		}
		if strings.Contains(lowerCSP, "*") {
			addFinding(report, SeverityLow, "安全响应头", "CSP 过于宽松", "当前 Content-Security-Policy 中存在通配符来源。", "收紧来源范围，只允许必要域名。", csp)
		}
	}

	if report.UsesHTTPS {
		hsts := headers.Get("Strict-Transport-Security")
		if hsts != "" {
			if maxAge := parseHSTSMaxAge(hsts); maxAge > 0 && maxAge < 15552000 {
				addFinding(report, SeverityMedium, "安全响应头", "HSTS max-age 偏低", fmt.Sprintf("当前 HSTS 为 `%s`。", hsts), "建议至少配置 15552000 秒，长期建议 31536000 秒。", hsts)
			}
			if !strings.Contains(strings.ToLower(hsts), "includesubdomains") {
				addFinding(report, SeverityLow, "安全响应头", "HSTS 未覆盖子域", fmt.Sprintf("当前 HSTS 为 `%s`。", hsts), "如业务允许，可增加 includeSubDomains。", hsts)
			}
		}
	}

	xcto := strings.ToLower(headers.Get("X-Content-Type-Options"))
	if xcto != "" && xcto != "nosniff" {
		addFinding(report, SeverityMedium, "安全响应头", "X-Content-Type-Options 配置异常", fmt.Sprintf("当前值为 `%s`。", headers.Get("X-Content-Type-Options")), "建议设置为 nosniff。", headers.Get("X-Content-Type-Options"))
	}

	contentType := strings.ToLower(headers.Get("Content-Type"))
	if strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "charset=") {
		addFinding(report, SeverityLow, "安全响应头", "HTML 响应未显式声明字符集", fmt.Sprintf("当前 Content-Type 为 `%s`。", headers.Get("Content-Type")), "为 HTML 响应明确配置 charset，例如 utf-8。", headers.Get("Content-Type"))
	}

	coop := strings.ToLower(headers.Get("Cross-Origin-Opener-Policy"))
	if coop != "" && coop != "same-origin" && coop != "same-origin-allow-popups" {
		addFinding(report, SeverityLow, "安全响应头", "COOP 配置偏弱", fmt.Sprintf("当前 COOP 为 `%s`。", headers.Get("Cross-Origin-Opener-Policy")), "优先评估使用 same-origin。", headers.Get("Cross-Origin-Opener-Policy"))
	}

	xpcdp := strings.ToLower(headers.Get("X-Permitted-Cross-Domain-Policies"))
	if xpcdp != "" && xpcdp != "none" {
		addFinding(report, SeverityLow, "安全响应头", "X-Permitted-Cross-Domain-Policies 未设为 none", fmt.Sprintf("当前值为 `%s`。", headers.Get("X-Permitted-Cross-Domain-Policies")), "建议设置为 none。", headers.Get("X-Permitted-Cross-Domain-Policies"))
	}
}

func collectCookieFindings(report *Report, snapshot responseSnapshot) {
	for _, cookie := range snapshot.Cookies {
		if !cookie.HttpOnly {
			addFinding(report, SeverityMedium, "Cookie", "Cookie 缺少 HttpOnly", fmt.Sprintf("Cookie `%s` 未设置 HttpOnly。", cookie.Name), "为敏感 Cookie 开启 HttpOnly，降低 XSS 后被读取的风险。", cookie.Name)
		}

		if report.UsesHTTPS && !cookie.Secure {
			addFinding(report, SeverityMedium, "Cookie", "Cookie 缺少 Secure", fmt.Sprintf("Cookie `%s` 未设置 Secure。", cookie.Name), "在 HTTPS 站点上为敏感 Cookie 设置 Secure。", cookie.Name)
		}

		if cookie.SameSite == http.SameSiteDefaultMode {
			addFinding(report, SeverityLow, "Cookie", "Cookie 未显式设置 SameSite", fmt.Sprintf("Cookie `%s` 未显式声明 SameSite。", cookie.Name), "按业务需要设置 SameSite=Lax/Strict/None。", cookie.Name)
		}

		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			addFinding(report, SeverityMedium, "Cookie", "SameSite=None Cookie 缺少 Secure", fmt.Sprintf("Cookie `%s` 使用 SameSite=None 但未设置 Secure。", cookie.Name), "SameSite=None 的 Cookie 必须同时启用 Secure。", cookie.Name)
		}
	}
}

func collectCORSFindings(ctx context.Context, report *Report, targetURL string) {
	snapshot, err := performRequest(ctx, newHTTPClient(true), http.MethodGet, targetURL, map[string]string{
		"Origin": "https://security-check.invalid",
	})
	if err != nil {
		return
	}

	acao := snapshot.Headers.Get("Access-Control-Allow-Origin")
	acac := strings.ToLower(snapshot.Headers.Get("Access-Control-Allow-Credentials"))

	switch {
	case acao == "*" && acac == "true":
		addFinding(report, SeverityHigh, "CORS", "CORS 允许任意来源并携带凭证", "Access-Control-Allow-Origin 为 `*`，同时 Access-Control-Allow-Credentials 为 `true`。", "禁止将通配符来源与凭证同时使用，改为显式白名单。", fmt.Sprintf("ACAO=%s, ACAC=%s", acao, acac))
	case acao == "https://security-check.invalid" && acac == "true":
		addFinding(report, SeverityHigh, "CORS", "CORS 可能反射任意来源", "服务端将探测来源原样回显到 Access-Control-Allow-Origin，且允许携带凭证。", "将允许来源改为明确白名单，不要反射任意 Origin。", fmt.Sprintf("ACAO=%s, ACAC=%s", acao, acac))
	case acao == "*":
		addFinding(report, SeverityLow, "CORS", "CORS 对所有来源开放", "检测到 Access-Control-Allow-Origin 为 `*`。", "确认该接口是否需要公开跨域，若不需要请收紧为白名单。", "ACAO=*")
	}

	preflight, preflightErr := performRequest(ctx, newHTTPClient(false), http.MethodOptions, targetURL, map[string]string{
		"Origin":                         "https://security-check.invalid",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "authorization,content-type",
	})
	if preflightErr != nil {
		return
	}

	acah := preflight.Headers.Get("Access-Control-Allow-Headers")
	acam := strings.ToUpper(preflight.Headers.Get("Access-Control-Allow-Methods"))
	aceh := preflight.Headers.Get("Access-Control-Expose-Headers")

	if strings.Contains(acah, "*") {
		addFinding(report, SeverityLow, "CORS", "CORS 允许任意请求头", "Access-Control-Allow-Headers 包含 `*`。", "按实际需要显式声明允许的请求头。", acah)
	}

	if strings.Contains(aceh, "*") {
		addFinding(report, SeverityLow, "CORS", "CORS 暴露所有响应头", "Access-Control-Expose-Headers 包含 `*`。", "仅暴露业务确实需要被前端读取的响应头。", aceh)
	}

	if strings.Contains(acam, "PUT") || strings.Contains(acam, "DELETE") || strings.Contains(acam, "PATCH") {
		addFinding(report, SeverityLow, "CORS", "CORS 预检允许敏感方法", fmt.Sprintf("预检返回的方法为 `%s`。", preflight.Headers.Get("Access-Control-Allow-Methods")), "确认跨域场景是否确需允许这些状态变更方法。", preflight.Headers.Get("Access-Control-Allow-Methods"))
	}
}

func collectMethodFindings(ctx context.Context, report *Report, targetURL string) {
	snapshot, err := performRequest(ctx, newHTTPClient(true), http.MethodOptions, targetURL, nil)
	if err != nil {
		return
	}

	methods := parseMethods(snapshot.Headers.Get("Allow"), snapshot.Headers.Get("Public"))
	report.SupportedMethods = methods

	for _, method := range methods {
		switch method {
		case http.MethodTrace:
			addFinding(report, SeverityHigh, "HTTP 方法", "服务器允许 TRACE 方法", "TRACE 可能被用于诊断回显和某些中间件链路上的风险场景。", "禁用 TRACE 方法。", strings.Join(methods, ", "))
		case http.MethodPut, http.MethodDelete, http.MethodConnect:
			addFinding(report, SeverityMedium, "HTTP 方法", "暴露高风险 HTTP 方法", fmt.Sprintf("检测到允许方法 `%s`。", method), "确认该方法是否确有业务需要；对公网站点应尽量关闭不必要方法。", strings.Join(methods, ", "))
		}
	}
}

func collectDiscoveryFindings(ctx context.Context, report *Report, targetURL string) {
	securityTxtURL := joinURLPath(targetURL, "/.well-known/security.txt")
	securitySnapshot, err := performRequest(ctx, newHTTPClient(true), http.MethodGet, securityTxtURL, nil)
	if err != nil || securitySnapshot.StatusCode >= 400 {
		addFinding(report, SeverityLow, "公开文件", "缺少 security.txt", "未在 `/.well-known/security.txt` 发现安全联系文件。", "为站点添加 security.txt，方便外部安全研究者合规报告问题。", securityTxtURL)
	}

	robotsURL := joinURLPath(targetURL, "/robots.txt")
	robotsSnapshot, robotsErr := performRequest(ctx, newHTTPClient(true), http.MethodGet, robotsURL, nil)
	if robotsErr == nil && robotsSnapshot.StatusCode < 400 {
		if containsSensitiveRobotsRule(robotsSnapshot.BodySnippet) {
			addFinding(report, SeverityLow, "公开文件", "robots.txt 暴露敏感路径线索", "robots.txt 中出现了可能指向后台或敏感目录的规则。", "确认这些路径本身已做好鉴权与访问控制，不要仅依赖 robots.txt 隐藏。", robotsURL)
		}
	}

	sitemapURL := joinURLPath(targetURL, "/sitemap.xml")
	sitemapSnapshot, sitemapErr := performRequest(ctx, newHTTPClient(true), http.MethodGet, sitemapURL, nil)
	if sitemapErr == nil && sitemapSnapshot.StatusCode < 400 && strings.Contains(strings.ToLower(sitemapSnapshot.BodySnippet), "<loc>http://") {
		addFinding(report, SeverityLow, "公开文件", "sitemap.xml 中存在 HTTP 链接", "检测到 sitemap.xml 中可能包含非 HTTPS 链接。", "将 sitemap.xml 中的链接统一为 HTTPS。", sitemapURL)
	}
}

func collectSensitiveExposureFindings(ctx context.Context, report *Report, targetURL string) {
	paths := []struct {
		path           string
		title          string
		severity       Severity
		recommendation string
	}{
		{path: "/.git/HEAD", title: "疑似暴露 Git 仓库元数据", severity: SeverityHigh, recommendation: "禁止公开访问 `.git` 目录，并确认仓库历史中没有敏感信息。"},
		{path: "/.git/config", title: "疑似暴露 Git 配置文件", severity: SeverityHigh, recommendation: "禁止公开访问 `.git` 目录，并确认远程仓库地址和历史提交中没有敏感信息。"},
		{path: "/.svn/entries", title: "疑似暴露 SVN 元数据", severity: SeverityHigh, recommendation: "禁止公开访问 `.svn` 目录。"},
		{path: "/.DS_Store", title: "疑似暴露目录索引文件", severity: SeverityMedium, recommendation: "移除 `.DS_Store` 并禁止其公网访问。"},
		{path: "/.env", title: "疑似暴露环境配置文件", severity: SeverityHigh, recommendation: "禁止公开访问 `.env`，并立即轮换其中可能泄露的密钥。"},
		{path: "/config.php.bak", title: "疑似暴露备份配置文件", severity: SeverityHigh, recommendation: "移除配置备份文件并轮换其中可能泄露的密钥。"},
		{path: "/package.json", title: "疑似暴露前端依赖清单", severity: SeverityLow, recommendation: "确认依赖清单是否需要公网访问；结合依赖审计工具检查已知漏洞。"},
		{path: "/package-lock.json", title: "疑似暴露前端锁文件", severity: SeverityMedium, recommendation: "限制锁文件公网访问，并对依赖版本做漏洞审计。"},
		{path: "/yarn.lock", title: "疑似暴露前端锁文件", severity: SeverityMedium, recommendation: "限制锁文件公网访问，并对依赖版本做漏洞审计。"},
		{path: "/pnpm-lock.yaml", title: "疑似暴露前端锁文件", severity: SeverityMedium, recommendation: "限制锁文件公网访问，并对依赖版本做漏洞审计。"},
		{path: "/composer.json", title: "疑似暴露 PHP 依赖清单", severity: SeverityLow, recommendation: "确认依赖清单是否需要公网访问，并对 Composer 依赖做漏洞审计。"},
		{path: "/composer.lock", title: "疑似暴露 PHP 锁文件", severity: SeverityMedium, recommendation: "限制锁文件公网访问，并对依赖版本做漏洞审计。"},
		{path: "/requirements.txt", title: "疑似暴露 Python 依赖清单", severity: SeverityLow, recommendation: "确认依赖清单是否需要公网访问，并对 Python 依赖做漏洞审计。"},
		{path: "/Pipfile.lock", title: "疑似暴露 Python 锁文件", severity: SeverityMedium, recommendation: "限制锁文件公网访问，并对依赖版本做漏洞审计。"},
		{path: "/poetry.lock", title: "疑似暴露 Python 锁文件", severity: SeverityMedium, recommendation: "限制锁文件公网访问，并对依赖版本做漏洞审计。"},
		{path: "/phpinfo.php", title: "疑似暴露 phpinfo 页面", severity: SeverityHigh, recommendation: "删除 phpinfo 调试页面，避免暴露环境细节。"},
		{path: "/server-status", title: "疑似暴露服务器状态页", severity: SeverityHigh, recommendation: "为状态页增加访问控制，或直接关闭公网访问。"},
		{path: "/debug/pprof/", title: "疑似暴露性能分析端点", severity: SeverityHigh, recommendation: "限制调试与性能分析端点的公网访问。"},
		{path: "/actuator/env", title: "疑似暴露 Actuator 环境信息", severity: SeverityHigh, recommendation: "限制环境与配置端点的公网访问，并检查是否泄露敏感配置。"},
		{path: "/openapi.json", title: "开放 API 描述文件可公网访问", severity: SeverityLow, recommendation: "确认是否需要公开文档；如不需要，请限制访问。"},
		{path: "/swagger-ui/", title: "Swagger UI 可公网访问", severity: SeverityLow, recommendation: "若仅供内部使用，请增加鉴权或网络访问限制。"},
		{path: "/actuator/health", title: "Actuator 健康检查可公网访问", severity: SeverityMedium, recommendation: "限制运维接口的公网访问，必要时增加鉴权。"},
		{path: "/metrics", title: "疑似暴露监控指标端点", severity: SeverityMedium, recommendation: "限制指标端点的公网访问。"},
		{path: "/error.log", title: "疑似暴露错误日志文件", severity: SeverityHigh, recommendation: "移除日志文件公网访问，并检查是否泄露敏感信息。"},
		{path: "/access.log", title: "疑似暴露访问日志文件", severity: SeverityHigh, recommendation: "移除日志文件公网访问，并检查是否泄露敏感信息。"},
		{path: "/debug.log", title: "疑似暴露调试日志文件", severity: SeverityHigh, recommendation: "移除调试日志公网访问，并清理其中可能包含的敏感信息。"},
		{path: "/backup.zip", title: "疑似暴露备份文件", severity: SeverityHigh, recommendation: "移除公网备份文件，并轮换其中可能泄露的数据或密钥。"},
		{path: "/backup.tar.gz", title: "疑似暴露备份文件", severity: SeverityHigh, recommendation: "移除公网备份文件，并轮换其中可能泄露的数据或密钥。"},
		{path: "/dump.sql", title: "疑似暴露数据库导出文件", severity: SeverityHigh, recommendation: "移除数据库导出文件公网访问，并轮换敏感凭据。"},
	}

	for _, item := range paths {
		snapshot, err := performRequest(ctx, newHTTPClient(false), http.MethodGet, joinURLPath(targetURL, item.path), nil)
		if err != nil {
			continue
		}
		if snapshot.StatusCode == http.StatusOK || snapshot.StatusCode == http.StatusPartialContent {
			addFinding(report, item.severity, "敏感暴露", item.title, fmt.Sprintf("检测到 `%s` 返回 HTTP %d。", item.path, snapshot.StatusCode), item.recommendation, joinURLPath(targetURL, item.path))
		}
	}
}

func collectExposureFindings(report *Report, snapshot responseSnapshot) {
	server := snapshot.Headers.Get("Server")
	if server != "" {
		addFinding(report, SeverityLow, "敏感暴露", "暴露 Server 头", fmt.Sprintf("检测到 Server 头为 `%s`。", server), "尽量减少或隐藏不必要的服务器实现信息。", server)
	}

	xPoweredBy := snapshot.Headers.Get("X-Powered-By")
	if xPoweredBy != "" {
		addFinding(report, SeverityLow, "敏感暴露", "暴露 X-Powered-By 头", fmt.Sprintf("检测到 X-Powered-By 为 `%s`。", xPoweredBy), "移除或隐藏技术栈暴露信息。", xPoweredBy)
	}

	if snapshot.StatusCode >= http.StatusInternalServerError {
		addFinding(report, SeverityMedium, "敏感暴露", "站点返回 5xx 状态码", fmt.Sprintf("检测期间收到 HTTP %d。", snapshot.StatusCode), "检查服务端异常处理、错误页面和后端可用性。", "")
	}

	lowerBody := strings.ToLower(snapshot.BodySnippet)
	if strings.Contains(lowerBody, "<title>index of") || strings.Contains(lowerBody, "directory listing for") {
		addFinding(report, SeverityMedium, "敏感暴露", "疑似开启目录浏览", "页面内容中出现目录索引特征。", "关闭目录浏览，避免文件结构被枚举。", report.FinalURL)
	}

	if strings.Contains(lowerBody, "traceback") || strings.Contains(lowerBody, "stack trace") || strings.Contains(lowerBody, "exception") {
		addFinding(report, SeverityMedium, "敏感暴露", "页面疑似暴露异常信息", "响应内容中包含异常或堆栈关键字。", "隐藏详细错误栈，仅向用户返回通用错误页，并记录到后端日志。", report.FinalURL)
	}
}

func collectAppSurfaceFindings(report *Report, surface htmlSurface, snapshot responseSnapshot) {
	if surface.HasLoginForm && !surface.HasCSRFTokenField {
		addFinding(report, SeverityMedium, "CSRF", "POST 表单疑似缺少 CSRF Token", "检测到可能的登录或提交表单，但未识别到常见 CSRF Token 字段。", "为所有状态变更请求加入 CSRF Token，并在服务端校验。", strings.Join(surface.FormActions, ", "))
	}

	if surface.HasFileUpload {
		if !surface.HasCSRFTokenField {
			addFinding(report, SeverityMedium, "文件上传", "上传表单疑似缺少 CSRF 防护", "检测到文件上传表单，但未识别到常见 CSRF Token 字段。", "为上传表单增加 CSRF Token 校验。", strings.Join(surface.FormActions, ", "))
		}
		if !surface.HasUploadAcceptRestriction {
			addFinding(report, SeverityLow, "文件上传", "上传表单未声明前端文件类型限制", "文件上传控件未发现 `accept` 限制。", "在前端增加 accept 限制，并在服务端做 MIME、扩展名和内容校验。", strings.Join(surface.FileInputNames, ", "))
		}
	}

	if surface.HasInlineScript && !surface.HasCSP {
		addFinding(report, SeverityMedium, "XSS", "页面存在内联脚本且缺少 CSP", "检测到页面包含内联脚本，同时缺少 Content-Security-Policy。", "为页面配置严格 CSP，并逐步减少内联脚本。", report.FinalURL)
	}

	if surface.HasInlineEventHandlers && !surface.HasCSP {
		addFinding(report, SeverityLow, "XSS", "页面存在内联事件处理器且缺少 CSP", "检测到 onclick/onload 等内联事件处理器。", "避免内联事件处理器，改为脚本中绑定事件，并配合 CSP。", report.FinalURL)
	}

	if surface.HasDangerousDOMSinks {
		addFinding(report, SeverityMedium, "XSS", "页面包含危险 DOM Sink", "检测到 innerHTML、document.write、eval、insertAdjacentHTML 等高风险模式。", "减少危险 DOM API，统一使用安全 DOM 构造与输出编码。", strings.Join(surface.DOMSinkKeywords, ", "))
	}

	if surface.HasLoginForm && !surface.HasCaptcha {
		addFinding(report, SeverityLow, "暴力破解", "登录入口未发现明显 CAPTCHA 或人机校验痕迹", "检测到登录表单，但未识别到常见验证码标记。", "结合限流、锁定策略、二次验证或 CAPTCHA 降低暴力破解风险。", strings.Join(surface.FormActions, ", "))
	}

	if surface.HasLoginGETForm {
		addFinding(report, SeverityHigh, "认证与会话", "登录表单疑似使用 GET 提交", "检测到密码输入面，并发现 GET 表单。", "登录与敏感表单必须使用 POST 提交，并避免敏感参数出现在 URL 中。", strings.Join(surface.FormActions, ", "))
	}

	if surface.HasInsecureFormAction {
		addFinding(report, SeverityHigh, "页面与前端面", "HTTPS 页面存在提交到 HTTP 的表单", "检测到表单 action 指向非 HTTPS 地址。", "将所有表单提交统一改为 HTTPS。", strings.Join(surface.InsecureFormActions, ", "))
	}

	if report.UsesHTTPS && len(surface.MixedContentURLs) > 0 {
		addFinding(report, SeverityMedium, "页面与前端面", "HTTPS 页面存在混合内容", "检测到页面中包含 `http://` 资源引用。", "将脚本、样式、图片、iframe 等资源统一切换为 HTTPS。", strings.Join(surface.MixedContentURLs, ", "))
	}

	if surface.HasTargetBlankNoNoopener {
		addFinding(report, SeverityLow, "页面与前端面", "新窗口链接缺少 noopener", "检测到 `target=_blank` 链接但未发现 `rel=noopener`。", "为外链增加 `rel=\"noopener noreferrer\"`。", strings.Join(surface.TargetBlankLinks, ", "))
	}

	if len(surface.ExternalScriptsWithoutSRI) > 0 {
		addFinding(report, SeverityLow, "页面与前端面", "外部脚本缺少 SRI", "检测到通过网络加载的外部脚本未声明 integrity。", "为 CDN/第三方脚本增加 SRI 校验，并固定版本。", strings.Join(surface.ExternalScriptsWithoutSRI, ", "))
	}

	if len(surface.SourceMapHints) > 0 {
		addFinding(report, SeverityLow, "页面与前端面", "页面暴露 Source Map 线索", "响应内容中出现 sourceMappingURL 或 `.map` 线索。", "生产环境避免暴露未清理的 sourcemap，或限制其访问。", strings.Join(surface.SourceMapHints, ", "))
	}

	if len(surface.RedirectParams) > 0 {
		addFinding(report, SeverityLow, "开放重定向", "发现疑似重定向参数", "检测到常见重定向参数名，需进一步确认是否可跳转到任意外部地址。", "对跳转目标做白名单校验，禁止任意外链跳转。", strings.Join(surface.RedirectParams, ", "))
	}

	if len(surface.IncludeParams) > 0 {
		addFinding(report, SeverityLow, "文件包含", "发现疑似文件/模板包含参数", "检测到参数名可能参与文件、页面或模板选择。", "对文件路径参数做严格白名单校验，禁止直接拼接路径。", strings.Join(surface.IncludeParams, ", "))
	}

	if len(surface.CommandParams) > 0 {
		addFinding(report, SeverityLow, "命令注入", "发现疑似命令执行参数", "检测到参数名可能参与系统命令或网络诊断功能。", "避免拼接系统命令；使用安全 API，并对参数做白名单校验。", strings.Join(surface.CommandParams, ", "))
	}

	if len(surface.SQLParams) > 0 {
		addFinding(report, SeverityLow, "SQL 注入", "发现疑似数据查询参数", "检测到常见查询参数名，需重点复测 SQL 注入与盲注风险。", "后端统一使用参数化查询，禁止字符串拼接 SQL。", strings.Join(surface.SQLParams, ", "))
	}

	if len(surface.XSSParams) > 0 {
		addFinding(report, SeverityLow, "XSS", "发现高风险输入反射面", "检测到常见文本输入参数名，建议重点复测反射型、存储型和 DOM XSS。", "输出统一做上下文编码，前端避免危险 DOM API，后端做输入净化。", strings.Join(surface.XSSParams, ", "))
	}

	if len(surface.SSRFParams) > 0 {
		addFinding(report, SeverityLow, "SSRF", "发现疑似 SSRF 参数", "检测到常见 URL/回调/抓取类参数。", "对服务端发起请求的目标地址做白名单和私网限制，禁止访问元数据和内网地址。", strings.Join(surface.SSRFParams, ", "))
	}

	if len(surface.TraversalParams) > 0 {
		addFinding(report, SeverityLow, "路径遍历", "发现疑似路径参数", "检测到可能参与文件读取、下载或目录访问的参数。", "对路径参数做白名单校验，禁止 `../`、绝对路径和任意文件拼接。", strings.Join(surface.TraversalParams, ", "))
	}

	if len(surface.TemplateParams) > 0 {
		addFinding(report, SeverityLow, "模板注入", "发现疑似模板/视图参数", "检测到可能影响模板名称、视图选择或渲染逻辑的参数。", "模板名称统一走白名单映射，禁止用户输入直接参与模板表达式或路径。", strings.Join(surface.TemplateParams, ", "))
	}

	if len(surface.DeserializeParams) > 0 {
		addFinding(report, SeverityLow, "反序列化", "发现疑似序列化对象参数", "检测到可能承载序列化内容的参数名。", "避免反序列化不可信数据；若必须使用，加入签名校验与类型白名单。", strings.Join(surface.DeserializeParams, ", "))
	}

	cacheControl := strings.ToLower(snapshot.Headers.Get("Cache-Control"))
	if (surface.HasLoginForm || len(snapshot.Cookies) > 0) && !strings.Contains(cacheControl, "no-store") {
		addFinding(report, SeverityLow, "认证与会话", "敏感页面响应未显式禁止缓存", "检测到登录/会话相关页面，但 Cache-Control 未包含 no-store。", "为认证相关页面响应增加 `Cache-Control: no-store`。", snapshot.Headers.Get("Cache-Control"))
	}
}

func collectIdentityFindings(report *Report, surface htmlSurface, snapshot responseSnapshot) {
	if surface.HasLoginForm && !surface.HasPasswordPolicyHint {
		addFinding(report, SeverityLow, "身份与权限", "登录表单未发现明显密码强度约束线索", "未检测到 minlength、pattern 等密码输入限制线索。", "在前后端同时增加密码强度校验，并结合泄露密码拦截策略。", strings.Join(surface.FormActions, ", "))
	}

	if len(surface.IDORParams) > 0 {
		addFinding(report, SeverityLow, "IDOR", "发现疑似对象标识参数", "检测到常见资源标识参数名，例如 user_id、order_id、account_id。", "所有资源访问必须在服务端做对象级鉴权，不能仅依赖前端隐藏字段或 URL 不可见。", strings.Join(surface.IDORParams, ", "))
	}

	if len(surface.RoleFields) > 0 {
		addFinding(report, SeverityLow, "权限绕过", "页面暴露角色/权限相关字段", "检测到 role、is_admin、permission 等字段。", "关键权限字段只能在服务端生成和校验，不信任前端提交值。", strings.Join(surface.RoleFields, ", "))
	}

	if hasBearerLikeSurface(snapshot, surface) {
		addFinding(report, SeverityLow, "会话劫持", "页面存在令牌使用面", "检测到 Bearer/JWT 或会话类字段线索。", "对令牌启用短时效、绑定上下文、Secure/HttpOnly/SameSite，并避免在可读脚本环境暴露敏感令牌。", report.FinalURL)
	}
}

func collectBusinessLogicFindings(report *Report, surface htmlSurface) {
	if len(surface.SensitiveBusinessParams) > 0 {
		addFinding(report, SeverityLow, "参数篡改", "发现关键业务参数", "检测到价格、数量、角色、状态、优惠等关键字段。", "关键业务字段必须在服务端重新计算和校验，不能直接信任客户端提交值。", strings.Join(surface.SensitiveBusinessParams, ", "))
	}

	if len(surface.APIPaths) > 0 {
		addFinding(report, SeverityLow, "API 滥用", "发现 API 调用面", "页面中检测到 API 路径或接口调用线索。", "对接口增加鉴权、限流、签名或幂等控制，并校验所有关键参数。", strings.Join(surface.APIPaths, ", "))
	}

	if surface.HasReplaySensitiveForm && !surface.HasCSRFTokenField {
		addFinding(report, SeverityMedium, "重放攻击", "敏感业务表单缺少明显一次性令牌线索", "检测到支付、优惠券、验证码或订单相关表单，但未发现明显防重放令牌线索。", "增加幂等键、一次性 token、时效校验和服务端去重。", strings.Join(surface.FormActions, ", "))
	}

	if surface.HasRaceSensitiveSurface {
		addFinding(report, SeverityLow, "条件竞争", "发现疑似并发敏感业务字段", "检测到库存、余额、数量、额度等并发敏感字段。", "在服务端使用事务、乐观锁/悲观锁或原子更新，防止并发绕过。", strings.Join(surface.RaceFields, ", "))
	}

	if surface.HasScrapingSensitiveSurface {
		addFinding(report, SeverityLow, "爬虫与数据抓取", "页面存在批量抓取价值较高的数据面", "检测到列表/API/搜索等易被批量抓取的线索。", "增加速率限制、行为风控、分页限制和访问审计。", strings.Join(surface.APIPaths, ", "))
	}
}

func collectInfraSupplyChainFindings(report *Report, finalURL string, surface htmlSurface) {
	if len(surface.ExposedManifestPaths) > 0 {
		addFinding(report, SeverityMedium, "依赖漏洞", "公网暴露依赖/构建清单", "检测到 package/composer/pip 等依赖清单可公网访问。", "限制这些文件的公网访问，并结合依赖审计工具定期扫描已知漏洞。", strings.Join(surface.ExposedManifestPaths, ", "))
	}

	if len(surface.ExternalScriptHosts) > 0 {
		addFinding(report, SeverityLow, "第三方脚本污染", "页面依赖第三方脚本", "检测到外部脚本来源。", "审计第三方脚本必要性，固定版本并配合 SRI、CSP 与最小权限原则。", strings.Join(surface.ExternalScriptHosts, ", "))
	}

	host := extractHost(finalURL)
	if host != "" {
		if cname, err := net.LookupCNAME(host); err == nil {
			lowerCNAME := strings.ToLower(cname)
			if strings.Contains(lowerCNAME, "cloudfront.net") || strings.Contains(lowerCNAME, "azureedge.net") || strings.Contains(lowerCNAME, "github.io") || strings.Contains(lowerCNAME, "amazonaws.com") {
				addFinding(report, SeverityLow, "DNS/CDN/对象存储", "站点使用第三方托管或 CDN", fmt.Sprintf("检测到 CNAME 为 `%s`。", cname), "确认 DNS、CDN、对象存储桶和源站权限配置正确，定期检查是否存在悬空子域或未授权公开访问。", cname)
			}
		}
	}
}

func collectReflectionFindings(ctx context.Context, report *Report, targetURL string, surface htmlSurface) {
	candidates := make([]string, 0)
	candidates = append(candidates, surface.XSSParams...)
	candidates = append(candidates, surface.SQLParams...)
	candidates = append(candidates, surface.RedirectParams...)
	candidates = append(candidates, "q", "search", "query")

	probeValue := "portdesk-reflect-check-7f3a9b"
	checked := 0
	for _, candidate := range candidates {
		if checked >= 3 {
			break
		}
		probeURL, err := addOrSetQueryParam(targetURL, candidate, probeValue)
		if err != nil {
			continue
		}
		snapshot, reqErr := performRequest(ctx, newHTTPClient(true), http.MethodGet, probeURL, nil)
		if reqErr != nil {
			continue
		}
		checked++
		if strings.Contains(snapshot.BodySnippet, probeValue) {
			addFinding(report, SeverityLow, "主动探针", "检测到输入值被页面直接反射", fmt.Sprintf("参数 `%s` 的探测值出现在响应内容中。", candidate), "进一步复测输出上下文，确认是否存在反射型 XSS 或 HTML 注入。", candidate)
			return
		}
	}
}

func collectOpenRedirectValidationFindings(ctx context.Context, report *Report, targetURL string, surface htmlSurface) {
	for i, param := range surface.RedirectParams {
		if i >= 3 {
			break
		}
		probeURL, err := addOrSetQueryParam(targetURL, param, "https://security-check.invalid/portdesk-open-redirect")
		if err != nil {
			continue
		}
		snapshot, reqErr := performRequest(ctx, newHTTPClient(false), http.MethodGet, probeURL, nil)
		if reqErr != nil {
			continue
		}
		location := snapshot.Headers.Get("Location")
		if snapshot.StatusCode >= 300 && snapshot.StatusCode < 400 && strings.HasPrefix(location, "https://security-check.invalid/") {
			addFinding(report, SeverityHigh, "主动探针", "开放重定向验证命中", fmt.Sprintf("参数 `%s` 可将响应重定向到外部地址。", param), "为跳转目标增加白名单校验，禁止任意外链跳转。", location)
			return
		}
	}
}

func buildDVWACoverage(surface htmlSurface, report Report) []CoverageItem {
	return []CoverageItem{
		{Name: "Brute Force", Status: coverageStatus(surface.HasLoginForm, "需重点复测"), Notes: notesOrDefault(surface.HasLoginForm, "检测到登录表单，已对齐暴力破解类目；建议结合限流、锁定和二次验证人工复测。", "当前页面未发现明显登录入口。")},
		{Name: "Command Injection", Status: coverageStatus(len(surface.CommandParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.CommandParams) > 0, "发现疑似命令类参数，已纳入命令注入类目。", "未发现明显命令类参数。")},
		{Name: "CSRF", Status: coverageStatus(surface.HasPOSTForm, "已启发式检查"), Notes: notesOrDefault(surface.HasPOSTForm, "已检查 POST 表单及 CSRF Token 线索。", "当前页面未发现明显 POST 表单。")},
		{Name: "File Inclusion", Status: coverageStatus(len(surface.IncludeParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.IncludeParams) > 0, "发现疑似文件/模板包含参数。", "未发现明显文件包含参数。")},
		{Name: "File Upload", Status: coverageStatus(surface.HasFileUpload, "已启发式检查"), Notes: notesOrDefault(surface.HasFileUpload, "检测到上传表单，已检查 CSRF 与前端限制线索。", "未发现文件上传入口。")},
		{Name: "Insecure CAPTCHA", Status: coverageStatus(surface.HasLoginForm, "需业务流复测"), Notes: notesOrDefault(surface.HasLoginForm, "登录入口已纳入 CAPTCHA/防自动化复测范围。", "未发现明显登录入口。")},
		{Name: "SQL Injection", Status: coverageStatus(len(surface.SQLParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.SQLParams) > 0, "发现疑似查询参数，已纳入 SQL 注入复测范围。", "未发现明显查询参数。")},
		{Name: "SQL Injection (Blind)", Status: coverageStatus(len(surface.SQLParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.SQLParams) > 0, "与 SQL 注入共用参数面，建议单独做盲注验证。", "未发现明显查询参数。")},
		{Name: "Weak Session IDs", Status: coverageStatus(hasSessionCookie(report), "已启发式检查"), Notes: notesOrDefault(hasSessionCookie(report), "已检查会话 Cookie 基础特征与安全属性。", "本次响应未发现明显会话 Cookie。")},
		{Name: "XSS (DOM)", Status: coverageStatus(surface.HasInlineScript || len(surface.XSSParams) > 0, "需重点复测"), Notes: notesOrDefault(surface.HasInlineScript || len(surface.XSSParams) > 0, "已纳入 DOM XSS 覆盖，建议结合前端路由和 DOM API 人工复测。", "未发现明显 DOM XSS 线索。")},
		{Name: "XSS (Reflected)", Status: coverageStatus(len(surface.XSSParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.XSSParams) > 0, "发现高风险输入参数，已纳入反射型 XSS 范围。", "未发现明显反射输入面。")},
		{Name: "XSS (Stored)", Status: coverageStatus(surface.HasPOSTForm || len(surface.XSSParams) > 0, "需业务流复测"), Notes: notesOrDefault(surface.HasPOSTForm || len(surface.XSSParams) > 0, "发现可提交输入面，已纳入存储型 XSS 范围。", "当前页面未发现明显提交型输入面。")},
		{Name: "CSP Bypass", Status: coverageStatus(reportHasCategory(report, "安全响应头"), "已启发式检查"), Notes: notesOrDefault(reportHasCategory(report, "安全响应头"), "已检查 CSP 缺失、弱策略与宽松配置。", "当前页面未返回相关头部信息。")},
		{Name: "Open Redirect", Status: coverageStatus(len(surface.RedirectParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.RedirectParams) > 0, "发现疑似跳转参数，已纳入开放重定向范围。", "未发现明显重定向参数。")},
		{Name: "SSRF", Status: coverageStatus(len(surface.SSRFParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.SSRFParams) > 0, "发现 URL/回调/抓取类参数。", "未发现明显 SSRF 参数。")},
		{Name: "Path Traversal", Status: coverageStatus(len(surface.TraversalParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.TraversalParams) > 0, "发现文件/路径类参数。", "未发现明显路径参数。")},
		{Name: "Template Injection", Status: coverageStatus(len(surface.TemplateParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.TemplateParams) > 0, "发现模板/视图类参数。", "未发现明显模板参数。")},
		{Name: "Deserialization", Status: coverageStatus(len(surface.DeserializeParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.DeserializeParams) > 0, "发现疑似序列化对象参数。", "未发现明显反序列化参数。")},
		{Name: "IDOR", Status: coverageStatus(len(surface.IDORParams) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.IDORParams) > 0, "发现对象标识参数。", "未发现明显对象标识参数。")},
		{Name: "Parameter Tampering", Status: coverageStatus(len(surface.SensitiveBusinessParams) > 0, "已启发式检查"), Notes: notesOrDefault(len(surface.SensitiveBusinessParams) > 0, "发现价格、数量、角色、状态等关键字段。", "未发现明显关键业务字段。")},
		{Name: "Replay Attack", Status: coverageStatus(surface.HasReplaySensitiveForm, "需业务流复测"), Notes: notesOrDefault(surface.HasReplaySensitiveForm, "发现支付/验证码/优惠券类表单。", "未发现明显重放敏感表单。")},
		{Name: "Race Condition", Status: coverageStatus(surface.HasRaceSensitiveSurface, "需业务流复测"), Notes: notesOrDefault(surface.HasRaceSensitiveSurface, "发现库存、余额、数量等并发敏感字段。", "未发现明显并发敏感字段。")},
		{Name: "API Abuse", Status: coverageStatus(len(surface.APIPaths) > 0, "需重点复测"), Notes: notesOrDefault(len(surface.APIPaths) > 0, "发现 API 调用面。", "未发现明显 API 调用线索。")},
	}
}

type htmlSurface struct {
	HasPOSTForm                 bool
	HasLoginForm                bool
	HasLoginGETForm             bool
	HasFileUpload               bool
	HasCSRFTokenField           bool
	HasCaptcha                  bool
	HasInlineScript             bool
	HasInlineEventHandlers      bool
	HasDangerousDOMSinks        bool
	HasUploadAcceptRestriction  bool
	HasCSP                      bool
	HasInsecureFormAction       bool
	HasTargetBlankNoNoopener    bool
	HasPasswordPolicyHint       bool
	HasReplaySensitiveForm      bool
	HasRaceSensitiveSurface     bool
	HasScrapingSensitiveSurface bool
	FormActions                 []string
	FileInputNames              []string
	InsecureFormActions         []string
	MixedContentURLs            []string
	TargetBlankLinks            []string
	DOMSinkKeywords             []string
	ExternalScriptsWithoutSRI   []string
	ExternalScriptHosts         []string
	SourceMapHints              []string
	ExposedManifestPaths        []string
	RedirectParams              []string
	IncludeParams               []string
	CommandParams               []string
	SQLParams                   []string
	XSSParams                   []string
	SSRFParams                  []string
	TraversalParams             []string
	TemplateParams              []string
	DeserializeParams           []string
	IDORParams                  []string
	SensitiveBusinessParams     []string
	RoleFields                  []string
	APIPaths                    []string
	RaceFields                  []string
}

func analyzeHTMLSurface(finalURL string, body string) htmlSurface {
	lower := strings.ToLower(body)
	surface := htmlSurface{
		HasInlineScript: strings.Contains(lower, "<script") && !strings.Contains(lower, "<script src="),
		HasCaptcha:      strings.Contains(lower, "captcha") || strings.Contains(lower, "hcaptcha") || strings.Contains(lower, "recaptcha"),
		HasCSP:          strings.Contains(lower, "content-security-policy"),
	}

	formActionRe := regexp.MustCompile(`(?is)<form[^>]*action=["']?([^"'\s>]+)?[^>]*>`)
	formMethodRe := regexp.MustCompile(`(?is)<form[^>]*method=["']?post["']?[^>]*>`)
	formMethodGetRe := regexp.MustCompile(`(?is)<form[^>]*method=["']?get["']?[^>]*>`)
	passwordRe := regexp.MustCompile(`(?is)<input[^>]*type=["']?password["']?[^>]*>`)
	fileRe := regexp.MustCompile(`(?is)<input[^>]*type=["']?file["']?[^>]*>`)
	tokenRe := regexp.MustCompile(`(?is)<input[^>]*(name|id)=["']?[^"'>]*(csrf|token|nonce|authenticity)[^"'>]*["']?[^>]*>`)
	acceptRe := regexp.MustCompile(`(?is)<input[^>]*type=["']?file["']?[^>]*accept=["'][^"']+["'][^>]*>`)
	paramRe := regexp.MustCompile(`(?i)[?&]([a-z0-9_\-]+)=`)
	nameRe := regexp.MustCompile(`(?is)<input[^>]*name=["']?([^"'\s>]+)`)
	httpResourceRe := regexp.MustCompile(`(?is)(src|href|action)=["'](http://[^"']+)["']`)
	targetBlankRe := regexp.MustCompile(`(?is)<a[^>]*target=["']?_blank["']?[^>]*>`)
	inlineEventRe := regexp.MustCompile(`(?is)\son[a-z]+\s*=`)
	externalScriptRe := regexp.MustCompile(`(?is)<script[^>]*src=["'](https?://[^"']+)["'][^>]*>`)
	sourceMapRe := regexp.MustCompile(`(?i)(sourcemappingurl=|\.map\b)`)
	minLengthRe := regexp.MustCompile(`(?is)<input[^>]*type=["']?password["']?[^>]*minlength=["']?[8-9][0-9]*["']?`)
	patternRe := regexp.MustCompile(`(?is)<input[^>]*type=["']?password["']?[^>]*pattern=`)
	apiPathRe := regexp.MustCompile(`(?i)(/api/[a-z0-9/_\-]+|/graphql|/rest/[a-z0-9/_\-]+)`)

	surface.HasPOSTForm = formMethodRe.MatchString(body)
	surface.HasLoginForm = passwordRe.MatchString(body)
	surface.HasLoginGETForm = surface.HasLoginForm && formMethodGetRe.MatchString(body)
	surface.HasFileUpload = fileRe.MatchString(body)
	surface.HasCSRFTokenField = tokenRe.MatchString(body)
	surface.HasUploadAcceptRestriction = acceptRe.MatchString(body)
	surface.HasInlineEventHandlers = inlineEventRe.MatchString(body)
	surface.HasPasswordPolicyHint = minLengthRe.MatchString(body) || patternRe.MatchString(body)
	surface.HasScrapingSensitiveSurface = strings.Contains(lower, "pagination") || strings.Contains(lower, "load more") || strings.Contains(lower, "/api/")

	domSinks := []string{"innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "eval(", "Function("}
	for _, sink := range domSinks {
		if strings.Contains(body, sink) {
			surface.HasDangerousDOMSinks = true
			surface.DOMSinkKeywords = appendUnique(surface.DOMSinkKeywords, sink)
		}
	}

	for _, match := range formActionRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 && strings.TrimSpace(match[1]) != "" {
			surface.FormActions = appendUnique(surface.FormActions, match[1])
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(match[1])), "http://") {
				surface.HasInsecureFormAction = true
				surface.InsecureFormActions = appendUnique(surface.InsecureFormActions, match[1])
			}
		}
	}

	for _, match := range nameRe.FindAllStringSubmatch(body, -1) {
		if len(match) < 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(match[1]))
		switch {
		case isRedirectParam(name):
			surface.RedirectParams = appendUnique(surface.RedirectParams, name)
		case isSSRFParam(name):
			surface.SSRFParams = appendUnique(surface.SSRFParams, name)
		case isIncludeParam(name):
			surface.IncludeParams = appendUnique(surface.IncludeParams, name)
		case isTraversalParam(name):
			surface.TraversalParams = appendUnique(surface.TraversalParams, name)
		case isCommandParam(name):
			surface.CommandParams = appendUnique(surface.CommandParams, name)
		case isSQLParam(name):
			surface.SQLParams = appendUnique(surface.SQLParams, name)
		case isXSSParam(name):
			surface.XSSParams = appendUnique(surface.XSSParams, name)
		case isTemplateParam(name):
			surface.TemplateParams = appendUnique(surface.TemplateParams, name)
		case isDeserializeParam(name):
			surface.DeserializeParams = appendUnique(surface.DeserializeParams, name)
		case isIDORParam(name):
			surface.IDORParams = appendUnique(surface.IDORParams, name)
		case isSensitiveBusinessParam(name):
			surface.SensitiveBusinessParams = appendUnique(surface.SensitiveBusinessParams, name)
		case isRoleField(name):
			surface.RoleFields = appendUnique(surface.RoleFields, name)
		}
		if isRaceField(name) {
			surface.HasRaceSensitiveSurface = true
			surface.RaceFields = appendUnique(surface.RaceFields, name)
		}
		if isReplayField(name) {
			surface.HasReplaySensitiveForm = true
		}
	}

	for _, match := range fileRe.FindAllString(body, -1) {
		inputName := extractInputName(match)
		if inputName != "" {
			surface.FileInputNames = appendUnique(surface.FileInputNames, inputName)
		}
	}

	for _, match := range httpResourceRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 2 {
			surface.MixedContentURLs = appendUnique(surface.MixedContentURLs, match[2])
		}
	}

	for _, match := range targetBlankRe.FindAllString(body, -1) {
		lowerTag := strings.ToLower(match)
		if !strings.Contains(lowerTag, "noopener") {
			surface.HasTargetBlankNoNoopener = true
			surface.TargetBlankLinks = appendUnique(surface.TargetBlankLinks, strings.TrimSpace(match))
		}
	}

	for _, match := range externalScriptRe.FindAllStringSubmatch(body, -1) {
		if len(match) > 1 {
			host := extractHost(match[1])
			if host != "" {
				surface.ExternalScriptHosts = appendUnique(surface.ExternalScriptHosts, host)
			}
			lowerTag := strings.ToLower(match[0])
			if !strings.Contains(lowerTag, "integrity=") {
				surface.ExternalScriptsWithoutSRI = appendUnique(surface.ExternalScriptsWithoutSRI, match[1])
			}
		}
	}

	for _, match := range sourceMapRe.FindAllString(body, -1) {
		surface.SourceMapHints = appendUnique(surface.SourceMapHints, match)
	}

	for _, match := range apiPathRe.FindAllString(body, -1) {
		surface.APIPaths = appendUnique(surface.APIPaths, match)
	}

	for _, match := range paramRe.FindAllStringSubmatch(finalURL+" "+body, -1) {
		if len(match) < 2 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(match[1]))
		switch {
		case isRedirectParam(name):
			surface.RedirectParams = appendUnique(surface.RedirectParams, name)
		case isSSRFParam(name):
			surface.SSRFParams = appendUnique(surface.SSRFParams, name)
		case isIncludeParam(name):
			surface.IncludeParams = appendUnique(surface.IncludeParams, name)
		case isTraversalParam(name):
			surface.TraversalParams = appendUnique(surface.TraversalParams, name)
		case isCommandParam(name):
			surface.CommandParams = appendUnique(surface.CommandParams, name)
		case isSQLParam(name):
			surface.SQLParams = appendUnique(surface.SQLParams, name)
		case isXSSParam(name):
			surface.XSSParams = appendUnique(surface.XSSParams, name)
		case isTemplateParam(name):
			surface.TemplateParams = appendUnique(surface.TemplateParams, name)
		case isDeserializeParam(name):
			surface.DeserializeParams = appendUnique(surface.DeserializeParams, name)
		case isIDORParam(name):
			surface.IDORParams = appendUnique(surface.IDORParams, name)
		case isSensitiveBusinessParam(name):
			surface.SensitiveBusinessParams = appendUnique(surface.SensitiveBusinessParams, name)
		}
		if isRaceField(name) {
			surface.HasRaceSensitiveSurface = true
			surface.RaceFields = appendUnique(surface.RaceFields, name)
		}
		if isReplayField(name) {
			surface.HasReplaySensitiveForm = true
		}
	}

	return surface
}

func coverageStatus(condition bool, covered string) string {
	if condition {
		return covered
	}
	return "未发现入口"
}

func notesOrDefault(condition bool, positive string, negative string) string {
	if condition {
		return positive
	}
	return negative
}

func hasSessionCookie(report Report) bool {
	for _, finding := range report.Findings {
		if finding.Category == "Cookie" && strings.Contains(strings.ToLower(finding.Title), "cookie") {
			return true
		}
	}
	return false
}

func reportHasCategory(report Report, category string) bool {
	for _, finding := range report.Findings {
		if finding.Category == category {
			return true
		}
	}
	return false
}

func appendUnique(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	if slices.Contains(items, value) {
		return items
	}
	return append(items, value)
}

func extractInputName(input string) string {
	nameRe := regexp.MustCompile(`(?is)name=["']?([^"'\s>]+)`)
	match := nameRe.FindStringSubmatch(input)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func isRedirectParam(name string) bool {
	keywords := []string{"url", "next", "target", "redirect", "return", "returnto", "continue", "dest", "destination"}
	return containsKeyword(name, keywords)
}

func isSSRFParam(name string) bool {
	keywords := []string{"url", "uri", "link", "endpoint", "callback", "webhook", "feed", "fetch", "proxy", "image_url"}
	return containsKeyword(name, keywords)
}

func isIncludeParam(name string) bool {
	keywords := []string{"file", "path", "page", "include", "template", "view", "lang"}
	return containsKeyword(name, keywords)
}

func isTraversalParam(name string) bool {
	keywords := []string{"file", "filepath", "path", "dir", "folder", "download", "document"}
	return containsKeyword(name, keywords)
}

func isCommandParam(name string) bool {
	keywords := []string{"cmd", "exec", "command", "ping", "host", "ip"}
	return containsKeyword(name, keywords)
}

func isSQLParam(name string) bool {
	keywords := []string{"id", "user", "uid", "search", "query", "keyword", "sort", "order", "filter"}
	return containsKeyword(name, keywords)
}

func isTemplateParam(name string) bool {
	keywords := []string{"template", "tpl", "view", "render", "layout"}
	return containsKeyword(name, keywords)
}

func isDeserializeParam(name string) bool {
	keywords := []string{"data", "payload", "state", "object", "serialized", "profile"}
	return containsKeyword(name, keywords)
}

func isIDORParam(name string) bool {
	keywords := []string{"user_id", "userid", "account_id", "order_id", "invoice_id", "customer_id", "member_id", "profile_id"}
	return containsKeyword(name, keywords)
}

func isSensitiveBusinessParam(name string) bool {
	keywords := []string{"price", "amount", "quantity", "qty", "discount", "coupon", "role", "status", "level", "balance", "limit"}
	return containsKeyword(name, keywords)
}

func isRoleField(name string) bool {
	keywords := []string{"role", "is_admin", "admin", "permission", "scope"}
	return containsKeyword(name, keywords)
}

func isRaceField(name string) bool {
	keywords := []string{"quantity", "qty", "stock", "inventory", "balance", "limit", "quota", "coupon"}
	return containsKeyword(name, keywords)
}

func isReplayField(name string) bool {
	keywords := []string{"pay", "payment", "coupon", "redeem", "sms", "otp", "code", "order"}
	return containsKeyword(name, keywords)
}

func isXSSParam(name string) bool {
	keywords := []string{"q", "s", "search", "name", "title", "message", "comment", "content", "text", "query"}
	return containsKeyword(name, keywords)
}

func containsKeyword(name string, keywords []string) bool {
	for _, keyword := range keywords {
		if name == keyword || strings.Contains(name, keyword) {
			return true
		}
	}
	return false
}

func addOrSetQueryParam(targetURL string, key string, value string) (string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set(key, value)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func hasBearerLikeSurface(snapshot responseSnapshot, surface htmlSurface) bool {
	auth := snapshot.Headers.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return true
	}
	body := strings.ToLower(snapshot.BodySnippet)
	if strings.Contains(body, "bearer ") || strings.Contains(body, "jwt") || strings.Contains(body, "access_token") {
		return true
	}
	return len(surface.RoleFields) > 0 && len(snapshot.Cookies) > 0
}

func extractHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

type responseSnapshot struct {
	URL         string
	StatusCode  int
	Headers     http.Header
	Cookies     []*http.Cookie
	BodySnippet string
	TLS         *ConnectionStateSnapshot
}

type ConnectionStateSnapshot struct {
	Version         uint16
	CipherSuiteName string
}

func newHTTPClient(followRedirects bool) *http.Client {
	client := &http.Client{
		Timeout: 12 * time.Second,
	}
	if !followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		return client
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("重定向次数过多")
		}
		return nil
	}

	return client
}

func performRequest(ctx context.Context, client *http.Client, method string, target string, headers map[string]string) (responseSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return responseSnapshot{}, err
	}
	req.Header.Set("User-Agent", "PortDesk-WebCheck/1.0")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return responseSnapshot{}, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	snapshot := responseSnapshot{
		URL:         resp.Request.URL.String(),
		StatusCode:  resp.StatusCode,
		Headers:     resp.Header.Clone(),
		Cookies:     resp.Cookies(),
		BodySnippet: string(bodyBytes),
	}

	if resp.TLS != nil {
		snapshot.TLS = &ConnectionStateSnapshot{
			Version:         resp.TLS.Version,
			CipherSuiteName: tls.CipherSuiteName(resp.TLS.CipherSuite),
		}
	}

	return snapshot, nil
}

func probeHTTPRedirect(ctx context.Context, targetURL string) (bool, string, error) {
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		return false, "", err
	}
	httpURL := "http://" + parsed.Host + parsed.RequestURI()
	snapshot, err := performRequest(ctx, newHTTPClient(true), http.MethodGet, httpURL, nil)
	if err != nil {
		return false, "", err
	}

	return strings.HasPrefix(snapshot.URL, "https://"), snapshot.URL, nil
}

func joinURLPath(baseURL string, extraPath string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	parsed.Path = extraPath
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func parseMethods(values ...string) []string {
	seen := make(map[string]struct{})
	methods := make([]string, 0)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			method := strings.ToUpper(strings.TrimSpace(part))
			if method == "" {
				continue
			}
			if _, ok := seen[method]; ok {
				continue
			}
			seen[method] = struct{}{}
			methods = append(methods, method)
		}
	}
	sort.Strings(methods)
	return methods
}

func containsSensitiveRobotsRule(content string) bool {
	lower := strings.ToLower(content)
	keywords := []string{"/admin", "/manage", "/internal", "/backup", "/private", "/debug"}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func parseHSTSMaxAge(value string) int {
	parts := strings.Split(value, ";")
	for _, part := range parts {
		item := strings.TrimSpace(strings.ToLower(part))
		if !strings.HasPrefix(item, "max-age=") {
			continue
		}
		seconds, err := strconv.Atoi(strings.TrimPrefix(item, "max-age="))
		if err != nil {
			return 0
		}
		return seconds
	}
	return 0
}

func addFinding(report *Report, severity Severity, category string, title string, details string, recommendation string, evidence string) {
	report.Findings = append(report.Findings, Finding{
		Severity:       severity,
		Category:       category,
		Title:          title,
		Details:        details,
		Recommendation: recommendation,
		Evidence:       evidence,
	})
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	default:
		return 1
	}
}

func tlsVersion(state *ConnectionStateSnapshot) string {
	if state == nil {
		return "未使用 TLS"
	}

	switch state.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "未知版本"
	}
}
