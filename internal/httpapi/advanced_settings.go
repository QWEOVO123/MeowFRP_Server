package httpapi

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"frp-control-server/internal/config"
)

func applyRuntimeTuning(cfg *config.Config, req updateSystemSettingsRequest) error {
	for _, field := range []struct {
		name, value string
		destination *time.Duration
	}{
		{"session_ttl", req.SessionTTL, &cfg.SessionTTL},
		{"runtime_token_ttl", req.RuntimeTokenTTL, &cfg.RuntimeTokenTTL},
		{"udp_connection_ttl", req.UDPConnectionTTL, &cfg.UDPConnectionTTL},
	} {
		if field.value == "" {
			continue
		}
		value, err := time.ParseDuration(strings.TrimSpace(field.value))
		if err != nil || value <= 0 {
			return fmt.Errorf("%s must be a positive duration", field.name)
		}
		*field.destination = value
	}
	if req.FRPBindAddr != "" {
		cfg.FRPBindAddr = strings.TrimSpace(req.FRPBindAddr)
	}
	if req.FRPProxyBindAddr != "" {
		cfg.FRPProxyBindAddr = strings.TrimSpace(req.FRPProxyBindAddr)
	}
	if req.ClientConfigComment != "" {
		cfg.ClientConfigComment = strings.TrimSpace(req.ClientConfigComment)
	}
	return nil
}

func prepareAdvancedSettings(cfg *config.Config) error {
	if cfg.ConfigurationMode == config.ConfigurationAutomatic {
		config.ApplyRecommended(cfg)
	}
	for _, address := range []string{cfg.FRPBindAddr, cfg.FRPProxyBindAddr} {
		if address != "" && address != "localhost" && net.ParseIP(address) == nil {
			return fmt.Errorf("FRP bind address must be an IP address or localhost")
		}
	}
	if cfg.Mode == config.ModeController && cfg.Controller.EdgeAccessEnabled {
		host, portText, err := net.SplitHostPort(cfg.Controller.ListenAddr)
		port, portErr := strconv.Atoi(portText)
		if err != nil || portErr != nil || port < 1 || port > 65535 || (host != "" && host != "localhost" && net.ParseIP(host) == nil) {
			return fmt.Errorf("mTLS listen address must be an IP address and port between 1 and 65535")
		}
	}
	return nil
}

func (s *Server) settingsNeedRestart(cfg config.Config) bool {
	s.mu.RLock()
	pending := s.restartRequired
	s.mu.RUnlock()
	return pending || (s.core != nil && s.core.Status(cfg).Running != cfg.EmbeddedFRPEnabled) ||
		(cfg.Mode == config.ModeController && cfg.Controller.EdgeAccessEnabled && s.controllerControl == nil)
}

// Saved preferences can differ from listeners still using the boot config.
// Keep the notice until process restart, even after a second unchanged save.
func (s *Server) noteSettingsRestart(cfg config.Config, changed bool) bool {
	s.mu.Lock()
	s.restartRequired = s.restartRequired || changed
	s.mu.Unlock()
	return s.settingsNeedRestart(cfg)
}
