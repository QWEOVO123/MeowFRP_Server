package httpapi

import (
	"frp-control-server/internal/config"
	"frp-control-server/internal/security"
	"golang.org/x/time/rate"
	"net/http"
	"strings"
	"time"
)

var clientAccountLoginLimiter = rate.NewLimiter(5, 10)

func (s *Server) clientAccountLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !clientAccountLoginLimiter.Allow() {
		writeError(w, http.StatusTooManyRequests, "登录请求过于频繁，请稍后重试")
		return
	}
	store := s.getStore()
	cfg := s.getConfig()
	if cfg.Mode != config.ModeController || store == nil {
		writeError(w, 503, "请连接已初始化的中心节点")
		return
	}
	var req struct {
		AccessToken string `json:"access_token"`
		ClientID    string `json:"client_id"`
	}
	if readJSON(r, &req) != nil || strings.TrimSpace(req.AccessToken) == "" || strings.TrimSpace(req.ClientID) == "" {
		writeError(w, 400, "请填写用户 Token 和设备标识")
		return
	}
	req.AccessToken = strings.TrimSpace(req.AccessToken)
	req.ClientID = strings.TrimSpace(req.ClientID)
	token, err := store.GetAccessTokenByHash(r.Context(), security.TokenHash(req.AccessToken))
	if err != nil || token.Status != "active" || (token.ExpiresAt != nil && !time.Now().Before(*token.ExpiresAt)) {
		writeError(w, 401, "Token 无效、已过期或已被禁用")
		return
	}
	u, err := store.GetUserByID(r.Context(), token.UserID)
	if err != nil || u.Role != "user" || u.Status != "active" {
		writeError(w, 401, "Token 所属用户不存在或已被禁用")
		return
	}
	nodeIDs, err := store.UserNodeIDs(r.Context(), u.ID)
	if err != nil {
		writeError(w, 500, "读取节点权限失败")
		return
	}
	allowed := map[string]bool{}
	for _, id := range nodeIDs {
		allowed[id] = true
	}
	items := []map[string]any{}
	if allowed["controller"] {
		if item := controllerDirectoryItem(cfg, r); item != nil {
			items = append(items, item)
		}
	}
	if cfg.Controller.EdgeAccessEnabled {
		nodes, err := store.ListPublicEdgeNodes(r.Context())
		if err != nil {
			writeError(w, 500, "读取节点列表失败")
			return
		}
		for _, n := range nodes {
			if !allowed[n.NodeID] {
				continue
			}
			online := false
			if s.controllerControl != nil {
				online, _ = s.controllerControl.NodeSession(n.NodeID)
			}
			items = append(items, map[string]any{"node_id": n.NodeID, "tag": n.Name, "api_url": n.PublicAPIURL, "online": online, "node_type": "edge"})
		}
	}
	if len(items) == 0 {
		writeError(w, 403, "该账号没有可用节点，请联系管理员分配节点权限")
		return
	}
	if client, err := store.GetClient(r.Context(), token.ID, req.ClientID); err == nil && client.Status == "banned" {
		writeError(w, 403, "此设备已被禁用")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "nodes": items})
}

func (s *Server) userNodeAccess(w http.ResponseWriter, r *http.Request) {
	id, err := parseID(r)
	if err != nil {
		writeError(w, 400, "invalid user id")
		return
	}
	store := s.getStore()
	u, err := store.GetUserByID(r.Context(), id)
	if err != nil || u.Role != "user" {
		writeError(w, 400, "请选择普通用户")
		return
	}
	nodes, err := store.ListEdgeNodes(r.Context())
	if err != nil {
		writeError(w, 500, "读取节点列表失败")
		return
	}
	valid := map[string]bool{"controller": true}
	options := []map[string]any{{"node_id": "controller", "name": s.getConfig().Node.Tag + "（中心）"}}
	for _, n := range nodes {
		if n.Status == "active" {
			valid[n.NodeID] = true
			options = append(options, map[string]any{"node_id": n.NodeID, "name": n.Name})
		}
	}
	if r.Method == http.MethodPut {
		var req struct {
			NodeIDs []string `json:"node_ids"`
		}
		if readJSON(r, &req) != nil {
			writeError(w, 400, "invalid request")
			return
		}
		for _, n := range req.NodeIDs {
			if !valid[n] {
				writeError(w, 400, "节点不存在或已禁用，请刷新后重试")
				return
			}
		}
		if err = store.SaveUserNodeAccess(r.Context(), id, req.NodeIDs); err != nil {
			writeError(w, 500, "保存节点权限失败")
			return
		}
		controllerAllowed := false
		for _, nodeID := range req.NodeIDs {
			if nodeID == "controller" {
				controllerAllowed = true
			}
		}
		if !controllerAllowed && s.core != nil {
			s.core.TerminateConnectionsForUser(id)
		}
	}
	ids, err := store.UserNodeIDs(r.Context(), id)
	if err != nil {
		writeError(w, 500, "读取节点权限失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "node_ids": ids, "nodes": options})
}
