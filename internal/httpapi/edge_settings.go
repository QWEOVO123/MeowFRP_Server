package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"frp-control-server/internal/config"
)

// Only non-secret, node-local tuning is exposed over the management channel.
// Controller addresses, enrollment credentials and PKI cannot be overwritten.
type edgeAdvancedSettings struct {
	ConfigurationMode  string                  `json:"configuration_mode"`
	ConnectionTuning   config.ConnectionTuning `json:"connection_tuning"`
	EmbeddedFRPEnabled bool                    `json:"embedded_frps_enabled"`
	FRPTransportTLS    bool                    `json:"frp_transport_tls"`
	FRPBindAddr        string                  `json:"frp_bind_addr"`
	FRPProxyBindAddr   string                  `json:"frp_proxy_bind_addr"`
	SessionTTL         string                  `json:"session_ttl"`
	RuntimeTokenTTL    string                  `json:"runtime_token_ttl"`
	UDPConnectionTTL   string                  `json:"udp_connection_ttl"`
	ClientComment      string                  `json:"client_config_comment"`
}

func edgeAdvancedSnapshot(cfg config.Config) edgeAdvancedSettings {
	return edgeAdvancedSettings{
		ConfigurationMode: cfg.ConfigurationMode, ConnectionTuning: cfg.ConnectionTuning,
		EmbeddedFRPEnabled: cfg.EmbeddedFRPEnabled, FRPTransportTLS: cfg.FRPTransportTLS,
		FRPBindAddr: cfg.FRPBindAddr, FRPProxyBindAddr: cfg.FRPProxyBindAddr,
		SessionTTL: cfg.SessionTTL.String(), RuntimeTokenTTL: cfg.RuntimeTokenTTL.String(),
		UDPConnectionTTL: cfg.UDPConnectionTTL.String(), ClientComment: cfg.ClientConfigComment,
	}
}

func applyEdgeAdvancedSettings(cfg *config.Config, req edgeAdvancedSettings) error {
	if req.ConfigurationMode != config.ConfigurationAutomatic && req.ConfigurationMode != config.ConfigurationManual {
		return fmt.Errorf("configuration_mode must be automatic or manual")
	}
	if strings.TrimSpace(req.FRPBindAddr) == "" || strings.TrimSpace(req.FRPProxyBindAddr) == "" ||
		strings.TrimSpace(req.SessionTTL) == "" || strings.TrimSpace(req.RuntimeTokenTTL) == "" || strings.TrimSpace(req.UDPConnectionTTL) == "" {
		return fmt.Errorf("edge advanced settings must contain bind addresses and positive timeouts")
	}
	if err := config.ValidateConnectionTuning(req.ConnectionTuning); err != nil {
		return err
	}
	// These two knobs belong to the center's mTLS listener, not an edge.
	if req.ConnectionTuning.MTLSHandshakeTimeoutSeconds != 0 || req.ConnectionTuning.DisableMTLSSessionTickets {
		return fmt.Errorf("mTLS listener settings belong to the center system settings")
	}
	cfg.ConfigurationMode = req.ConfigurationMode
	cfg.ConnectionTuning = req.ConnectionTuning
	cfg.EmbeddedFRPEnabled, cfg.FRPTransportTLS = req.EmbeddedFRPEnabled, req.FRPTransportTLS
	if err := applyRuntimeTuning(cfg, updateSystemSettingsRequest{
		FRPBindAddr: req.FRPBindAddr, FRPProxyBindAddr: req.FRPProxyBindAddr,
		SessionTTL: req.SessionTTL, RuntimeTokenTTL: req.RuntimeTokenTTL, UDPConnectionTTL: req.UDPConnectionTTL,
	}); err != nil {
		return err
	}
	cfg.ClientConfigComment = strings.TrimSpace(req.ClientComment)
	return prepareAdvancedSettings(cfg)
}

func (s *Server) updateEdgeAdvancedSettings(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	var req edgeAdvancedSettings
	if nodeID == "" || readJSON(r, &req) != nil {
		writeError(w, http.StatusBadRequest, "invalid edge advanced settings")
		return
	}
	if _, ok := s.edgeConfigurationCapabilities(w, r, nodeID, true); !ok {
		return
	}
	// Validate using an isolated edge config, never the center's own config.
	cfg := config.Config{Mode: config.ModeEdge}
	if err := applyEdgeAdvancedSettings(&cfg, req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, _ := json.Marshal(edgeAdvancedSnapshot(cfg))
	s.queueEdgeConfiguration(w, r, nodeID, "update_edge_advanced_settings", payload)
}
