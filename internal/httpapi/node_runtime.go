package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
)

func initializeNodeRuntimeFromRequest(cfg *config.Config, r *http.Request, tag string) {
	if strings.TrimSpace(cfg.Node.Tag) == "" {
		cfg.Node.Tag = strings.TrimSpace(tag)
	}
	if cfg.Node.Tag == "" {
		cfg.Node.Tag = "MeowFRP 节点"
	}
	if cfg.Node.FRPBindPort == 0 {
		cfg.Node.FRPBindPort = cfg.FRPServerPort
	}
	if cfg.Node.PortRangeStart == 0 {
		cfg.Node.PortRangeStart = 1024
	}
	if cfg.Node.PortRangeEnd == 0 {
		cfg.Node.PortRangeEnd = 65535
	}
	cfg.Node.Selectable = true
	if cfg.Node.PublicAPIURL == "" {
		cfg.Node.PublicAPIURL = externalRequestBaseURL(r)
	}
	if isLocalAdvertiseAddress(cfg.Node.FRPAdvertiseAddr) || cfg.Node.FRPAdvertiseAddr == "" {
		if cfg.Mode == config.ModeController {
			// Center setup obtains its address from server-side IPv4 discovery
			// or explicit input, never the browser/CDN/reverse-proxy hostname.
			if cfg.Node.FRPAdvertiseAddr == "" {
				cfg.Node.FRPAdvertiseAddr = "127.0.0.1"
			}
		} else {
			cfg.Node.FRPAdvertiseAddr = requestPublicHost(r)
		}
	}
	syncLegacyFRPFields(cfg)
}

func normalizeNodeRuntime(node config.NodeRuntimeConfig) config.NodeRuntimeConfig {
	node.Tag = strings.TrimSpace(node.Tag)
	node.PublicAPIURL = strings.TrimRight(strings.TrimSpace(node.PublicAPIURL), "/")
	node.FRPAdvertiseAddr = strings.TrimSpace(node.FRPAdvertiseAddr)
	return node
}

func validateNodeRuntime(node config.NodeRuntimeConfig) error {
	if node.Tag == "" {
		return fmt.Errorf("node tag is required")
	}
	if node.FRPAdvertiseAddr == "" {
		return fmt.Errorf("frp advertise address is required")
	}
	if err := validateFRPAdvertiseAddress(node.FRPAdvertiseAddr); err != nil {
		return err
	}
	if err := config.ValidateNodeRuntime(node); err != nil {
		return err
	}
	return validatePublicAPIURL(node.PublicAPIURL)
}

func validateFRPAdvertiseAddress(value string) error {
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return nil
	}
	// Address and control port are separate fields; do not accept a URL,
	// scheme, path, credentials or host:port as the FRP host.
	if value == "" || len(value) > 253 || strings.ContainsAny(value, ":/\\?#@[] \t\r\n") {
		return fmt.Errorf("FRP address must be an IP address or hostname without a scheme, port or path")
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("invalid FRP hostname")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return fmt.Errorf("invalid FRP hostname")
			}
		}
	}
	return nil
}

func validatePublicAPIURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("public_api_url must be an absolute HTTP(S) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("public_api_url must not contain credentials, a query, or a fragment")
	}
	if u.Scheme == "http" && !isLoopbackAPIHost(u.Hostname()) {
		return fmt.Errorf("public_api_url must use HTTPS for non-loopback hosts")
	}
	return nil
}

func isLoopbackAPIHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func syncLegacyFRPFields(cfg *config.Config) {
	cfg.FRPServerAddr = cfg.Node.FRPAdvertiseAddr
	cfg.FRPServerPort = cfg.Node.FRPBindPort
}

func externalRequestBaseURL(r *http.Request) string {
	scheme := "http"
	host := strings.TrimSpace(r.Host)
	if r.TLS != nil {
		scheme = "https"
	}
	if requestFromLoopbackProxy(r) {
		if forwarded := firstHeaderValue(r.Header.Get("X-Forwarded-Proto")); forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
		if forwardedHost := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host + "/api"
}

func requestPublicHost(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if requestFromLoopbackProxy(r) {
		if forwardedHost := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			host = forwardedHost
		}
	}
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	return strings.Trim(host, "[]")
}

func requestFromLoopbackProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func firstHeaderValue(value string) string {
	if before, _, ok := strings.Cut(value, ","); ok {
		value = before
	}
	return strings.TrimSpace(value)
}

func isLocalAdvertiseAddress(value string) bool {
	value = strings.TrimSpace(strings.Trim(value, "[]"))
	if value == "" || strings.EqualFold(value, "localhost") || value == "0.0.0.0" || value == "::" {
		return true
	}
	ip := net.ParseIP(value)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func validateNodeRemotePort(cfg config.Config, port int) error {
	if port < cfg.Node.PortRangeStart || port > cfg.Node.PortRangeEnd {
		return fmt.Errorf("remote port %d is outside node range %d-%d", port, cfg.Node.PortRangeStart, cfg.Node.PortRangeEnd)
	}
	for reserved, reason := range nodeReservedPorts(cfg) {
		if port == reserved {
			return fmt.Errorf("remote port %d is reserved for %s", port, reason)
		}
	}
	return nil
}

func intersectNodePortRange(policy *db.UserResourcePolicy, cfg config.Config) (*db.UserResourcePolicy, bool) {
	if policy == nil {
		return nil, false
	}
	intersected := *policy
	if intersected.PortStart < cfg.Node.PortRangeStart {
		intersected.PortStart = cfg.Node.PortRangeStart
	}
	if intersected.PortEnd == 0 || intersected.PortEnd > cfg.Node.PortRangeEnd {
		intersected.PortEnd = cfg.Node.PortRangeEnd
	}
	return &intersected, intersected.PortStart <= intersected.PortEnd
}

func nodeReservedPorts(cfg config.Config) map[int]string {
	reserved := map[int]string{}
	if cfg.Node.FRPBindPort > 0 {
		reserved[cfg.Node.FRPBindPort] = "frps control"
	}
	if port := portFromAddress(cfg.HTTPAddr); port > 0 {
		reserved[port] = "node API"
	}
	if cfg.Mode == config.ModeController {
		if port := portFromAddress(cfg.Controller.ListenAddr); port > 0 {
			reserved[port] = "controller mTLS"
		}
	}
	return reserved
}

func portFromAddress(value string) int {
	_, raw, err := net.SplitHostPort(value)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}
