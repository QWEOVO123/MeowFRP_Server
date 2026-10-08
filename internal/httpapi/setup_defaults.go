package httpapi

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

type publicIPv4Result struct {
	Address    string   `json:"address"`
	Candidates []string `json:"candidates"`
	Status     string   `json:"status"`
	Source     string   `json:"source"`
	Message    string   `json:"message"`
}

type setupIPCache struct {
	mu        sync.Mutex
	checkedAt time.Time
	result    publicIPv4Result
}

// Conservative exclusion of private, shared, documentation and special-purpose
// ranges: https://www.iana.org/assignments/iana-ipv4-special-registry/
var excludedPublicIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func publicIPv4(value string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}
	addr = addr.Unmap()
	if !addr.Is4() || !addr.IsGlobalUnicast() {
		return "", false
	}
	for _, prefix := range excludedPublicIPv4 {
		if prefix.Contains(addr) {
			return "", false
		}
	}
	return addr.String(), true
}

func publicInterfaceIPv4s() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	addresses := []string{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		} // Do not silently miss a second address.
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if value, ok := publicIPv4(ip.String()); ok {
				addresses = append(addresses, value)
			}
		}
	}
	return uniquePublicIPv4s(addresses), nil
}

func uniquePublicIPv4s(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if ip, ok := publicIPv4(value); ok {
			seen[ip] = true
		}
	}
	result := make([]string, 0, len(seen))
	for ip := range seen {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result
}

func decidePublicIPv4(values []string, source string, complete bool) publicIPv4Result {
	result := publicIPv4Result{Address: "127.0.0.1", Candidates: uniquePublicIPv4s(values), Status: "unavailable", Source: source, Message: "无法确定唯一公网 IPv4，暂保留 127.0.0.1，请手动填写服务器入站地址。"}
	if len(result.Candidates) > 1 {
		result.Status = "multiple"
		result.Message = "检测到多个公网 IPv4，暂保留 127.0.0.1，请手动选择用于 FRP 入站连接的地址。"
	} else if len(result.Candidates) == 1 && complete {
		result.Address = result.Candidates[0]
		result.Status = "unique"
		result.Message = "检测到唯一公网 IPv4，已作为 FRP 下发地址建议。"
		if source == "egress" {
			result.Message = "两个出口探测结果一致，已建议该公网 IPv4；NAT / 多公网 IP 云主机请核对它是否支持入站连接。"
		}
	}
	return result
}

func fetchEgressIPv4(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IP probe returned %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65))
	if err != nil || len(body) > 64 {
		return "", fmt.Errorf("invalid IP probe response")
	}
	if value, ok := publicIPv4(string(body)); ok {
		return value, nil
	}
	return "", fmt.Errorf("IP probe did not return a public IPv4")
}

func detectServerPublicIPv4(ctx context.Context) publicIPv4Result {
	local, err := publicInterfaceIPv4s()
	if err != nil {
		return decidePublicIPv4(nil, "interfaces", false)
	}
	if len(local) > 0 {
		return decidePublicIPv4(local, "interfaces", true)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		// Never use an environment proxy: that would discover the proxy's IP.
		Proxy: nil, TLSHandshakeTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Fixed HTTPS endpoints; no credentials, request host or visitor IP sent.
	endpoints := []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"}
	results := make(chan string, len(endpoints))
	for _, endpoint := range endpoints {
		go func(endpoint string) {
			value, err := fetchEgressIPv4(ctx, client, endpoint)
			if err != nil {
				value = ""
			}
			results <- value
		}(endpoint)
	}
	addresses := []string{}
	for range endpoints {
		select {
		case value := <-results:
			if value != "" {
				addresses = append(addresses, value)
			}
		case <-ctx.Done():
			return decidePublicIPv4(addresses, "egress", false)
		}
	}
	return decidePublicIPv4(addresses, "egress", len(addresses) == len(endpoints))
}

func (s *Server) setupIPv4(ctx context.Context) publicIPv4Result {
	s.setupIP.mu.Lock()
	defer s.setupIP.mu.Unlock()
	if !s.setupIP.checkedAt.IsZero() && time.Since(s.setupIP.checkedAt) < 10*time.Second {
		return s.setupIP.result
	}
	result := detectServerPublicIPv4(ctx)
	if ctx.Err() == nil {
		s.setupIP.result = result
		s.setupIP.checkedAt = time.Now()
	}
	return result
}

func (s *Server) setupDefaults(w http.ResponseWriter, r *http.Request) {
	if s.getConfig().Initialized {
		writeError(w, http.StatusConflict, "system already initialized")
		return
	}
	result := s.setupIPv4(r.Context())
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "frp_ipv4": result})
}
