package httpapi

import (
	"net/http"
	"strconv"
	"strings"
)

type clientHeartbeatRequest struct {
	AccessToken   string `json:"access_token"`
	ClientID      string `json:"client_id"`
	ClientVersion string `json:"client_version"`
	FRPCRunning   bool   `json:"frpc_running"`
	LeaseID       string `json:"lease_id"`
}

type clientCommandRequest struct {
	Command string `json:"command"`
	Message string `json:"message"`
}

func (s *Server) clientHeartbeat(w http.ResponseWriter, r *http.Request) {
	store := s.getStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "system setup required")
		return
	}
	var req clientHeartbeatRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.AccessToken == "" || req.ClientID == "" {
		writeError(w, http.StatusBadRequest, "access_token and client_id are required")
		return
	}
	_, _, client, reject := s.validateAccessTokenRequest(r, store, req.AccessToken, req.ClientID)
	if reject != nil {
		writeJSON(w, http.StatusOK, reject)
		return
	}
	if err := store.TouchClientHeartbeat(r.Context(), client.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	commands, err := store.PopQueuedClientCommands(r.Context(), client.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                        true,
		"status":                    "ok",
		"commands":                  commands,
		"heartbeat_interval":        int(clientHeartbeatInterval.Seconds()),
		"heartbeat_timeout_seconds": int(clientHeartbeatTimeout.Seconds()),
	})
}

func (s *Server) clientLogout(w http.ResponseWriter, r *http.Request) {
	store := s.getStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "system setup required")
		return
	}
	var req clientHeartbeatRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.AccessToken == "" || req.ClientID == "" {
		writeError(w, http.StatusBadRequest, "access_token and client_id are required")
		return
	}
	_, _, client, reject := s.validateExistingAccessTokenRequest(r, store, req.AccessToken, req.ClientID)
	if reject != nil {
		writeJSON(w, http.StatusOK, reject)
		return
	}

	terminated := s.terminateClientRuntime(r.Context(), *client, "client logout")
	deletedCommands, err := store.DeleteQueuedClientCommands(r.Context(), client.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := store.ClearClientPresence(r.Context(), client.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	store.Audit(r.Context(), "client", client.ID, "client_logout", "client", strconv.FormatInt(client.ID, 10), "terminated="+strconv.Itoa(terminated)+" deleted_commands="+strconv.FormatInt(deletedCommands, 10))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"status":           "logged_out",
		"terminated":       terminated,
		"deleted_commands": deletedCommands,
	})
}

func (s *Server) listConnectedClients(w http.ResponseWriter, r *http.Request) {
	if err := s.enforceClientHeartbeatTimeout(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	clients, err := s.store.ListRecentlySeenClients(r.Context(), int(clientHeartbeatTimeout.Seconds()))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                        true,
		"clients":                   clients,
		"heartbeat_timeout_seconds": int(clientHeartbeatTimeout.Seconds()),
	})
}

func (s *Server) enqueueClientCommand(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid client id")
		return
	}
	client, err := s.store.GetClientByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "client not found")
		return
	}
	var req clientCommandRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	command := normalizeClientCommand(req.Command)
	if command == "" {
		writeError(w, http.StatusBadRequest, "unsupported client command")
		return
	}
	message := strings.TrimSpace(req.Message)
	if message == "" {
		message = defaultClientCommandMessage(command)
	}
	admin := currentUser(r)
	queued, err := s.store.EnqueueClientCommand(r.Context(), client.ID, admin.ID, command, message)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if command == "stop_frpc" || command == "reauth" {
		_ = s.terminateClientRuntime(r.Context(), *client, "remote command: "+command)
	}
	s.store.Audit(r.Context(), "admin", admin.ID, "enqueue_client_command", "client", strconv.FormatInt(client.ID, 10), command)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "command": queued})
}

func normalizeClientCommand(command string) string {
	switch strings.ToLower(strings.TrimSpace(command)) {
	case "stop_frpc", "stop-frpc", "stop":
		return "stop_frpc"
	case "show_warning", "show-warning", "warning", "message":
		return "show_warning"
	case "reauth", "re_auth", "reauthorize":
		return "reauth"
	default:
		return ""
	}
}

func defaultClientCommandMessage(command string) string {
	switch command {
	case "show_warning":
		return "服务端检测到违规行为，请规范操作"
	case "stop_frpc":
		return "服务端要求关闭 frpc"
	case "reauth":
		return "服务端要求重新鉴权"
	default:
		return ""
	}
}
