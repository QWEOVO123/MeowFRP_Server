package frpcore

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/fatedier/frp/pkg/config/v1"
	splugin "github.com/fatedier/frp/pkg/plugin/server"
	frplog "github.com/fatedier/frp/pkg/util/log"
	frpserver "github.com/fatedier/frp/server"

	"frp-control-server/internal/config"
)

type Status struct {
	EmbeddedEnabled bool   `json:"embedded_enabled"`
	Running         bool   `json:"running"`
	BindAddr        string `json:"bind_addr,omitempty"`
	BindPort        int    `json:"bind_port,omitempty"`
}

func (m *Manager) StartEmbeddedFRPS(ctx context.Context, appCfg config.Config) error {
	if !appCfg.EmbeddedFRPEnabled {
		return nil
	}
	frpsCfg, err := BuildEmbeddedFRPSConfig(appCfg)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.running || m.frps != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	frplog.InitLogger(frpsCfg.Log.To, frpsCfg.Log.Level, int(frpsCfg.Log.MaxDays), frpsCfg.Log.DisablePrintColor)
	service, err := frpserver.NewService(frpsCfg)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.frps = service
	m.running = true
	m.mu.Unlock()

	go func() {
		service.Run(ctx)
		m.mu.Lock()
		if m.frps == service {
			m.frps = nil
			m.running = false
		}
		m.mu.Unlock()
	}()
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	service := m.frps
	m.frps = nil
	m.running = false
	m.mu.Unlock()
	if service == nil {
		return nil
	}
	return service.Close()
}

func (m *Manager) Status(appCfg config.Config) Status {
	m.mu.RLock()
	running := m.running
	m.mu.RUnlock()
	return Status{
		EmbeddedEnabled: appCfg.EmbeddedFRPEnabled,
		Running:         running,
		BindAddr:        appCfg.FRPBindAddr,
		BindPort:        appCfg.FRPServerPort,
	}
}

func BuildEmbeddedFRPSConfig(appCfg config.Config) (*v1.ServerConfig, error) {
	bindAddr := strings.TrimSpace(appCfg.FRPBindAddr)
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	proxyBindAddr := strings.TrimSpace(appCfg.FRPProxyBindAddr)
	if proxyBindAddr == "" {
		proxyBindAddr = bindAddr
	}
	bindPort := appCfg.FRPServerPort
	if bindPort <= 0 || bindPort > 65535 {
		return nil, fmt.Errorf("invalid frps bind port %d", bindPort)
	}

	cfg := &v1.ServerConfig{
		BindAddr:      bindAddr,
		BindPort:      bindPort,
		ProxyBindAddr: proxyBindAddr,
		Auth: v1.AuthServerConfig{
			Method: v1.AuthMethodToken,
		},
		Transport: v1.ServerTransportConfig{
			TLS: v1.TLSServerConfig{
				Force: appCfg.FRPTransportTLS,
			},
		},
		Log: v1.LogConfig{
			To:    "console",
			Level: "info",
		},
		HTTPPlugins: []v1.HTTPPluginOptions{
			{
				Name: "frp-control-server",
				Addr: controlPluginAddr(appCfg.HTTPAddr),
				Path: "/api/v1/frp/plugin",
				Ops: []string{
					splugin.OpLogin,
					splugin.OpNewProxy,
					splugin.OpCloseProxy,
					splugin.OpPing,
					splugin.OpNewWorkConn,
					splugin.OpNewUserConn,
				},
			},
		},
	}
	if err := cfg.Complete(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func controlPluginAddr(httpAddr string) string {
	addr := strings.TrimSpace(httpAddr)
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimRight(addr, "/")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			host = "127.0.0.1"
			port = strings.TrimPrefix(addr, ":")
		} else {
			host = addr
			port = "80"
		}
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}
