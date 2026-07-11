package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"frp-control-server/internal/dpi"
)

func (s *Server) listDPIEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	events, err := s.store.ListDPIEvents(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "events": events})
}

func (s *Server) listDPIPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.store.ListDPIPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policies": policies})
}

func (s *Server) getUserDPIPolicy(w http.ResponseWriter, r *http.Request) {
	userID, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	policy, err := s.store.GetDPIPolicy(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	policy.UserID = userID
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": policy})
}

type updateUserDPIPolicyRequest struct {
	Enabled              bool     `json:"enabled"`
	Mode                 string   `json:"mode"`
	EnabledDetectors     []string `json:"enabled_detectors"`
	BlockOnAnyFinding    bool     `json:"block_on_any_finding"`
	AllowHTTP            bool     `json:"allow_http"`
	AllowTLS             bool     `json:"allow_tls"`
	AllowQUIC            bool     `json:"allow_quic"`
	AllowEncryptedTunnel bool     `json:"allow_encrypted_tunnel"`
	MaxInspectBytes      int      `json:"max_inspect_bytes"`
	TemporaryBlockTTL    int      `json:"temporary_block_ttl_seconds"`
	EncryptedTunnelMode  string   `json:"encrypted_tunnel_mode"`
}

func (s *Server) updateUserDPIPolicy(w http.ResponseWriter, r *http.Request) {
	userID, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	var req updateUserDPIPolicyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := dpi.Mode(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = dpi.ModeMonitor
	}
	if mode != dpi.ModeMonitor && mode != dpi.ModeBlock {
		writeError(w, http.StatusBadRequest, "unsupported dpi mode")
		return
	}
	encryptedMode := dpi.Mode(strings.TrimSpace(req.EncryptedTunnelMode))
	if encryptedMode == "" {
		encryptedMode = dpi.ModeMonitor
	}
	if encryptedMode != dpi.ModeMonitor && encryptedMode != dpi.ModeBlock {
		writeError(w, http.StatusBadRequest, "unsupported encrypted tunnel mode")
		return
	}
	detectors := normalizeDPIDetectors(req.EnabledDetectors)
	if len(detectors) == 0 {
		detectors = dpi.DefaultPolicy().EnabledDetectors
	}
	policy, err := s.store.UpsertDPIPolicy(r.Context(), dpi.Policy{
		UserID:               userID,
		Enabled:              req.Enabled,
		Mode:                 mode,
		EnabledDetectors:     detectors,
		BlockOnAnyFinding:    req.BlockOnAnyFinding,
		AllowHTTP:            req.AllowHTTP,
		AllowTLS:             req.AllowTLS,
		AllowQUIC:            req.AllowQUIC,
		AllowEncryptedTunnel: req.AllowEncryptedTunnel,
		MaxInspectBytes:      req.MaxInspectBytes,
		TemporaryBlockTTL:    req.TemporaryBlockTTL,
		EncryptedTunnelMode:  encryptedMode,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	admin := currentUser(r)
	s.store.Audit(r.Context(), "admin", admin.ID, "update_dpi_policy", "user", strconv.FormatInt(userID, 10), "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "policy": policy})
}

func normalizeDPIDetectors(values []string) []string {
	allowed := map[string]bool{
		"http": true, "tls": true, "quic": true, "encrypted_tunnel": true,
	}
	seen := map[string]bool{}
	var out []string
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if allowed[value] && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}
