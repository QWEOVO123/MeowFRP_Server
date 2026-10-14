package httpapi

import (
	"net/http"

	"frp-control-server/internal/config"
)

func nodeTLSID(cfg config.Config) string {
	if cfg.Mode == config.ModeEdge {
		return cfg.Edge.NodeID
	}
	return "controller"
}

func (s *Server) prepareFRPIdentity(cfg config.Config) error {
	if s.core == nil || cfg.ConfigPath == "" {
		return nil
	}
	return s.core.EnsureTLSIdentity(cfg)
}

// Public certificates confer no user authorization. This endpoint must remain
// independent of MySQL so a database outage does not break trust delivery.
func (s *Server) frpTLSStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if !cfg.Initialized {
		writeError(w, 503, "node is not initialized")
		return
	}
	if s.core == nil {
		writeError(w, 503, "FRP runtime unavailable")
		return
	}
	includeCA := r.URL.Path == "/api/v1/client/frp-trust"
	p, ready := s.core.TLSPublic(includeCA)
	enabled := s.core.TLSRequired(cfg)
	if enabled && !ready {
		writeError(w, 503, "FRP trust identity is not ready")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": enabled, "node_id": nodeTLSID(cfg), "running": s.core.Status(cfg).Running, "ready": ready, "generation": p.Generation, "server_name": p.ServerName, "ca_pem": p.CAPEM, "ca_fingerprint": p.Fingerprint, "expires_at": p.NotAfter})
}

func (s *Server) resetFRPTLS(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if !cfg.Initialized || s.core == nil {
		writeError(w, 409, "node is not initialized")
		return
	}
	if err := s.core.ResetTLSIdentity(cfg, ""); err != nil {
		writeError(w, 500, "FRP identity reset failed: "+err.Error())
		return
	}
	if store := s.getStore(); store != nil {
		store.Audit(r.Context(), "admin", currentUser(r).ID, "reset_frp_tls", "node", nodeTLSID(cfg), "node-local FRP CA and key rotated")
	}
	p, _ := s.core.TLSPublic(false)
	writeJSON(w, 200, map[string]any{"ok": true, "identity": p, "existing_connections_preserved": true})
}
