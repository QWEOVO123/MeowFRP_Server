package httpapi

import (
	"net"
	"net/http"
	"strings"
)

func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	if s.core == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"connections": []any{},
			"blocked_ips": []any{},
		})
		return
	}
	cfg := s.getConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                         true,
		"connections":                s.core.ListConnections(cfg.UDPConnectionTTL),
		"blocked_ips":                s.core.ListBlockedInboundIPs(),
		"udp_connection_ttl":         cfg.UDPConnectionTTL.String(),
		"udp_connection_ttl_seconds": int(cfg.UDPConnectionTTL.Seconds()),
	})
}

func (s *Server) disconnectConnection(w http.ResponseWriter, r *http.Request) {
	if s.core == nil {
		writeError(w, http.StatusServiceUnavailable, "frp core is not available")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeError(w, http.StatusBadRequest, "connection id is required")
		return
	}
	if !s.core.TerminateTCPConnection(id) {
		writeError(w, http.StatusNotFound, "tcp connection not found")
		return
	}
	if admin := currentUser(r); admin != nil {
		s.getStore().Audit(r.Context(), "admin", admin.ID, "disconnect_connection", "connection", id, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type blockInboundIPRequest struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

func (s *Server) blockInboundIP(w http.ResponseWriter, r *http.Request) {
	if s.core == nil {
		writeError(w, http.StatusServiceUnavailable, "frp core is not available")
		return
	}
	var req blockInboundIPRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if net.ParseIP(req.IP) == nil {
		writeError(w, http.StatusBadRequest, "ip is invalid")
		return
	}
	var adminID int64
	if admin := currentUser(r); admin != nil {
		adminID = admin.ID
	}
	if store := s.getStore(); store != nil {
		if _, err := store.UpsertBlockedInboundIP(r.Context(), req.IP, req.Reason, adminID); err != nil {
			writeError(w, http.StatusInternalServerError, "save blocked ip failed: "+err.Error())
			return
		}
	}
	block := s.core.BlockInboundIP(req.IP, req.Reason)
	if adminID != 0 {
		s.getStore().Audit(r.Context(), "admin", adminID, "block_inbound_ip", "ip", req.IP, req.Reason)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "blocked_ip": block})
}

func (s *Server) unblockInboundIP(w http.ResponseWriter, r *http.Request) {
	if s.core == nil {
		writeError(w, http.StatusServiceUnavailable, "frp core is not available")
		return
	}
	ip := strings.TrimSpace(r.PathValue("ip"))
	if net.ParseIP(ip) == nil {
		writeError(w, http.StatusBadRequest, "ip is invalid")
		return
	}
	if store := s.getStore(); store != nil {
		if err := store.DeleteBlockedInboundIP(r.Context(), ip); err != nil {
			writeError(w, http.StatusInternalServerError, "delete blocked ip failed: "+err.Error())
			return
		}
	}
	s.core.UnblockInboundIP(ip)
	if admin := currentUser(r); admin != nil {
		s.getStore().Audit(r.Context(), "admin", admin.ID, "unblock_inbound_ip", "ip", ip, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
