package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/security"
)

type mutationResponse struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (s *Server) userIdentityCacheStates(w http.ResponseWriter, r *http.Request) {
	userID, err := parseID(r)
	if err != nil {
		writeError(w, 400, "invalid user id")
		return
	}
	states, err := s.getStore().UserIdentityCacheStates(r.Context(), userID)
	if err != nil {
		writeError(w, 500, "read user cache states failed")
		return
	}
	items := make([]map[string]any, 0, len(states))
	onlineNodes := map[string]bool{}
	if s.controllerControl != nil {
		for _, id := range s.controllerControl.ConnectedNodes() {
			onlineNodes[id] = true
		}
	}
	for _, v := range states {
		online := onlineNodes[v.NodeID]
		items = append(items, map[string]any{"node_id": v.NodeID, "node_name": v.NodeName, "boot_id": v.BootID, "applied_revision": v.AppliedRevision, "desired_revision": v.DesiredRevision, "cached_at": v.CachedAt, "cached": v.CachedAt != nil, "pending": v.Pending, "online": online})
	}
	writeJSON(w, 200, map[string]any{"ok": true, "user_id": userID, "nodes": items})
}

func (w *mutationResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *mutationResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

func (s *Server) pushConfigurationChanges(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		configuration := strings.HasPrefix(path, "/api/v1/admin/users") || strings.HasPrefix(path, "/api/v1/admin/tokens") || strings.HasPrefix(path, "/api/v1/admin/blocked-ips")
		if s.controllerControl == nil || !configuration || (r.Method != "POST" && r.Method != "PUT" && r.Method != "DELETE") {
			next.ServeHTTP(w, r)
			return
		}
		unlock := s.controllerControl.LockIdentityMutation()
		defer unlock()
		// Resolve token ownership before a rotation/deletion changes its record.
		var userID int64
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) > 4 {
			id, _ := strconv.ParseInt(parts[4], 10, 64)
			if parts[3] == "users" {
				userID = id
			}
			if parts[3] == "tokens" && id > 0 {
				if token, err := s.getStore().GetAccessTokenByID(r.Context(), id); err == nil {
					userID = token.UserID
				}
			}
		}
		response := &mutationResponse{ResponseWriter: w}
		next.ServeHTTP(response, r)
		if response.status >= 200 && response.status < 300 {
			if userID == 0 && (path == "/api/v1/admin/users" || path == "/api/v1/admin/tokens") {
				var created struct {
					User struct {
						ID int64 `json:"id"`
					} `json:"user"`
					Token struct {
						UserID int64 `json:"user_id"`
					} `json:"token"`
				}
				if json.Unmarshal(response.body.Bytes(), &created) == nil {
					userID = created.User.ID
					if userID == 0 {
						userID = created.Token.UserID
					}
				}
			}
			if userID > 0 {
				s.controllerControl.NotifyUserIdentityChanged(userID)
			} else if strings.HasPrefix(path, "/api/v1/admin/blocked-ips") {
				s.controllerControl.ScheduleBlockedIPPush()
			} else {
				s.controllerControl.ScheduleIdentityPush()
			}
		}
		status := response.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(response.body.Bytes())
	})
}

// Wait until each connected edge's requested snapshot has actually been stored.
func (s *Server) refreshEdgeReports(w http.ResponseWriter, r *http.Request) {
	if s.controllerControl == nil {
		writeError(w, 503, "controller stream is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	results := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, nodeID := range s.controllerControl.ConnectedNodes() {
		wg.Add(1)
		go func(nodeID string) {
			defer wg.Done()
			id, _, err := security.NewOpaqueToken("report_")
			if err == nil {
				var result cluster.CommandResult
				result, err = s.controllerControl.SendCommandAndWait(ctx, cluster.NodeCommand{NodeID: nodeID, CommandID: id, Command: "request_report", ExpiresAt: time.Now().Add(12 * time.Second)})
				if err == nil && result.Status != "succeeded" {
					err = fmt.Errorf("edge report failed: %s", result.Error)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				results[nodeID] = err.Error()
			} else {
				results[nodeID] = "updated"
			}
		}(nodeID)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"results": results})
}
