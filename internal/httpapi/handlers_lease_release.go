package httpapi

import (
	"net/http"
	"strings"
)

func (s *Server) releaseClientLease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccessToken string `json:"access_token"`
		ClientID    string `json:"client_id"`
		LeaseID     string `json:"lease_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, 400, "invalid request")
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.AccessToken == "" || req.ClientID == "" || req.LeaseID == "" {
		writeError(w, 400, "access_token, client_id and lease_id are required")
		return
	}
	s.bootstrapMu.Lock()
	defer s.bootstrapMu.Unlock()
	var released bool
	var err error
	if s.edgeState != nil {
		token, _, _, reject := s.edgeCredential(r, req.AccessToken, req.ClientID, false)
		if reject != nil {
			writeJSON(w, 403, reject)
			return
		}
		released, err = s.edgeState.ReleaseRuntimeLease(r.Context(), req.LeaseID, token.ID, req.ClientID)
	} else {
		store := s.getStore()
		if store == nil {
			writeError(w, 503, "database unavailable")
			return
		}
		token, _, _, reject := s.validateExistingAccessTokenRequest(r, store, req.AccessToken, req.ClientID)
		if reject != nil {
			writeJSON(w, 403, reject)
			return
		}
		released, err = store.ReleaseRuntimeLease(r.Context(), req.LeaseID, token.ID, req.ClientID)
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if released && s.core != nil {
		s.core.TerminateConnectionsForLease(req.LeaseID)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "released": released})
}
