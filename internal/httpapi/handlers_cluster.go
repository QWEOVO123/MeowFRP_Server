package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/frpcore"
	"frp-control-server/internal/security"
)

type setupEdgeRequest struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	DisplayName       string `json:"display_name"`
	NodeName          string `json:"node_name"`
	ControllerAddress string `json:"controller_address"`
	EnrollmentToken   string `json:"enrollment_token"`
}

func (s *Server) setupEdge(w http.ResponseWriter, r *http.Request) {
	var req setupEdgeRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.NodeName = strings.TrimSpace(req.NodeName)
	req.ControllerAddress = cluster.NormalizeControllerAddress(req.ControllerAddress)
	if req.Username == "" || req.NodeName == "" || req.ControllerAddress == "" || strings.TrimSpace(req.EnrollmentToken) == "" {
		writeError(w, http.StatusBadRequest, "administrator, node name, controller address and enrollment token are required")
		return
	}
	if err := validateAdminPassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := s.getConfig()
	if cfg.Initialized && cfg.ConfigState == "configured" {
		writeError(w, http.StatusConflict, "system already initialized")
		return
	}
	if cfg.ConfigState == "invalid" {
		if _, err := config.PreserveInvalidFile(cfg.ConfigPath); err != nil {
			writeError(w, 500, "preserve invalid config failed: "+err.Error())
			return
		}
	}
	hash, err := security.HashPassword(req.Password)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, privateKey, err := cluster.EnrollEdge(ctx, req.ControllerAddress, req.NodeName, strings.TrimSpace(req.EnrollmentToken))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := config.RandomSecret()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	cfg.ConfigVersion = 2
	cfg.ConfigState = "configured"
	cfg.ConfigError = ""
	cfg.Mode = config.ModeEdge
	cfg.Initialized = true
	cfg.CookieSecret = secret
	cfg.InitialAdmin = config.InitialAdminConfig{Username: req.Username, DisplayName: req.DisplayName, PasswordHash: hash}
	cfg.MySQLDSN = ""
	cfg.Edge.NodeID = result.NodeID
	cfg.Edge.NodeName = req.NodeName
	cfg.Edge.ControllerAPIAddr = req.ControllerAddress
	initializeNodeRuntimeFromRequest(&cfg, r, req.NodeName)
	cfg.Edge.ControllerAddr = result.MTLSAddress
	cfg.Edge.ServerName = result.MTLSServerName
	cfg.Edge.TLS = config.TLSFiles{CACertificateBase64: config.EncodePEM([]byte(result.CACertificate)), CertificateBase64: config.EncodePEM([]byte(result.Certificate)), PrivateKeyBase64: config.EncodePEM(privateKey)}
	if cfg.Edge.StatePath == "" {
		cfg.Edge.StatePath = "data/edge-state.db"
	}
	if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
		writeError(w, 500, "write config failed: "+err.Error())
		return
	}
	state, err := edgestate.Open(config.ResolvePath(cfg.ConfigPath, cfg.Edge.StatePath))
	if err != nil {
		writeError(w, 500, "open edge state failed: "+err.Error())
		return
	}
	s.mu.Lock()
	s.cfg = cfg
	s.edgeState = state
	s.store = nil
	s.mu.Unlock()
	state.SetDPIEventReporting(s.EdgeDPIEventsEnabled)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "mode": cfg.Mode, "node_id": result.NodeID, "certificate_expires_at": result.ExpiresAt, "restart_required": true, "config_path": cfg.ConfigPath})
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	mode := cfg.Mode
	if mode == "" {
		mode = "unconfigured"
	}
	features := map[string]bool{"global_users": mode == config.ModeController, "global_tokens": mode == config.ModeController, "node_management": mode == config.ModeController && cfg.Controller.EdgeAccessEnabled, "local_connections": true, "aggregated_connections": mode == config.ModeController, "edge_reporting": mode == config.ModeEdge}
	response := map[string]any{"ok": true, "mode": mode, "configured": cfg.ConfigState == "configured", "config_state": cfg.ConfigState, "features": features}
	if cfg.ConfigError != "" {
		response["config_error"] = cfg.ConfigError
	}
	if mode == config.ModeEdge {
		response["node_id"] = cfg.Edge.NodeID
		response["controller_connected"] = s.edgeClient != nil && s.edgeClient.Connected()
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) controllerPKIPaths(cfg config.Config) cluster.PKIPaths {
	defaults := cluster.DefaultPKIPaths(cfg.ConfigPath)
	if cfg.Controller.TLS.CAFile != "" {
		defaults.CAFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.CAFile)
	}
	if cfg.Controller.CAKeyFile != "" {
		defaults.CAKeyFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.CAKeyFile)
	}
	if cfg.Controller.TLS.CertFile != "" {
		defaults.CertFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.CertFile)
	}
	if cfg.Controller.TLS.KeyFile != "" {
		defaults.KeyFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.KeyFile)
	}
	return defaults
}

func controllerPKIMaterial(cfg config.Config) (cluster.PKIMaterial, error) {
	if cfg.Controller.TLS.CACertificateBase64 != "" {
		var m cluster.PKIMaterial
		var err error
		m.CACertificate, err = config.DecodePEM(cfg.Controller.TLS.CACertificateBase64)
		if err != nil {
			return m, err
		}
		m.CAPrivateKey, err = config.DecodePEM(cfg.Controller.TLS.CAPrivateKeyBase64)
		if err != nil {
			return m, err
		}
		m.Certificate, err = config.DecodePEM(cfg.Controller.TLS.CertificateBase64)
		if err != nil {
			return m, err
		}
		m.PrivateKey, err = config.DecodePEM(cfg.Controller.TLS.PrivateKeyBase64)
		return m, err
	}
	paths := cluster.DefaultPKIPaths(cfg.ConfigPath)
	if cfg.Controller.TLS.CAFile != "" {
		paths.CAFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.CAFile)
	}
	if cfg.Controller.CAKeyFile != "" {
		paths.CAKeyFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.CAKeyFile)
	}
	if cfg.Controller.TLS.CertFile != "" {
		paths.CertFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.CertFile)
	}
	if cfg.Controller.TLS.KeyFile != "" {
		paths.KeyFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.KeyFile)
	}
	return cluster.LoadPKIMaterial(paths)
}

func setControllerPKIMaterial(cfg *config.Config, m cluster.PKIMaterial) {
	cfg.Controller.TLS.CACertificateBase64 = config.EncodePEM(m.CACertificate)
	cfg.Controller.TLS.CAPrivateKeyBase64 = config.EncodePEM(m.CAPrivateKey)
	cfg.Controller.TLS.CertificateBase64 = config.EncodePEM(m.Certificate)
	cfg.Controller.TLS.PrivateKeyBase64 = config.EncodePEM(m.PrivateKey)
	cfg.Controller.TLS.CAFile = ""
	cfg.Controller.TLS.CertFile = ""
	cfg.Controller.TLS.KeyFile = ""
	cfg.Controller.CAKeyFile = ""
}

func ensureControllerPKI(cfg *config.Config) error {
	material, err := controllerPKIMaterial(*cfg)
	if err != nil {
		material, err = cluster.GenerateControllerPKI(cfg.Controller.PublicAddress)
		if err != nil {
			return err
		}
	}
	if cluster.ControllerCertificateCovers(material, cfg.Controller.PublicAddress) != nil {
		material, err = cluster.ReissueControllerServerCertificate(material, cfg.Controller.PublicAddress)
		if err != nil {
			return err
		}
	}
	setControllerPKIMaterial(cfg, material)
	return nil
}

func (s *Server) enrollEdgeNode(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if cfg.Mode != config.ModeController || !cfg.Controller.EdgeAccessEnabled || s.getStore() == nil {
		writeError(w, http.StatusNotFound, "edge enrollment is unavailable")
		return
	}
	secret := bearerToken(r)
	if secret == "" {
		writeError(w, http.StatusUnauthorized, "enrollment token is required")
		return
	}
	var req cluster.EnrollmentRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid enrollment request")
		return
	}
	req.NodeName = strings.TrimSpace(req.NodeName)
	if req.NodeName == "" || cluster.ParseCSRPublicKey(req.CSR) != nil {
		writeError(w, http.StatusBadRequest, "node name and valid CSR are required")
		return
	}
	material, err := controllerPKIMaterial(cfg)
	if err != nil {
		writeError(w, 500, "load controller PKI failed: "+err.Error())
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	newNode := nodeID == ""
	if nodeID != "" {
		if _, err := s.getStore().GetEdgeNode(r.Context(), nodeID); err != nil {
			writeError(w, http.StatusBadRequest, "requested edge node identity does not exist")
			return
		}
	} else {
		plainNodeID, _, err := security.NewOpaqueToken("node_")
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		nodeID = plainNodeID[:min(37, len(plainNodeID))]
	}
	certPEM, serial, expires, err := cluster.SignNodeCSRMaterial(material, nodeID, []byte(req.CSR))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	enrollmentSettings, err := s.getStore().ConsumeEnrollmentTokenSettings(r.Context(), secret)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	var options nodeEnrollmentOptions
	if enrollmentSettings != "" {
		if err := json.Unmarshal([]byte(enrollmentSettings), &options); err != nil {
			writeError(w, 500, "invalid saved enrollment settings")
			return
		}
		if newNode && options.Name != "" {
			req.NodeName = options.Name
		}
	}
	if err := s.getStore().UpsertEdgeNode(r.Context(), db.EdgeNode{NodeID: nodeID, Name: req.NodeName, CertificateSerial: serial, CapabilitiesJSON: "{}"}); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	if newNode && enrollmentSettings != "" {
		if err := s.getStore().UpdateEdgeNodeDirectory(r.Context(), nodeID, req.NodeName, options.PublicAPIURL, options.Selectable); err != nil {
			writeError(w, 500, err.Error())
			return
		}
	}
	if s.controllerControl != nil {
		s.controllerControl.RememberEnrolledNode(r.Context(), nodeID)
	}
	host, _, splitErr := net.SplitHostPort(cfg.Controller.PublicAddress)
	if splitErr != nil {
		host = cfg.Controller.PublicAddress
	}
	host = strings.Trim(host, "[]")
	writeJSON(w, http.StatusCreated, cluster.EnrollmentResponse{NodeID: nodeID, Certificate: string(certPEM), CACertificate: string(material.CACertificate), ExpiresAt: expires, MTLSAddress: cfg.Controller.PublicAddress, MTLSServerName: host})
}

type nodeEnrollmentOptions struct {
	Name         string `json:"name"`
	PublicAPIURL string `json:"public_api_url"`
	Selectable   bool   `json:"selectable"`
}

func (s *Server) createNodeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if !cfg.Controller.EdgeAccessEnabled {
		writeError(w, http.StatusConflict, "enable edge node access first")
		return
	}
	var req struct {
		ExpiresMinutes int                    `json:"expires_minutes"`
		Node           *nodeEnrollmentOptions `json:"node,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			writeError(w, 400, err.Error())
			return
		}
	}
	if req.ExpiresMinutes == 0 {
		req.ExpiresMinutes = 10
	}
	if req.ExpiresMinutes < 1 || req.ExpiresMinutes > 60 {
		writeError(w, 400, "token lifetime must be between 1 and 60 minutes")
		return
	}
	settings := ""
	if req.Node != nil {
		req.Node.Name = strings.TrimSpace(req.Node.Name)
		req.Node.PublicAPIURL = strings.TrimRight(strings.TrimSpace(req.Node.PublicAPIURL), "/")
		if len(req.Node.PublicAPIURL) > 512 {
			writeError(w, 400, "node API URL is too long")
			return
		}
		if len(req.Node.Name) > 128 {
			writeError(w, 400, "node name is too long")
			return
		}
		if req.Node.PublicAPIURL != "" || req.Node.Selectable {
			if err := validatePublicAPIURL(req.Node.PublicAPIURL); err != nil {
				writeError(w, 400, err.Error())
				return
			}
		}
		encoded, err := json.Marshal(req.Node)
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		settings = string(encoded)
	}
	if cfg.Controller.TLS.CACertificateBase64 == "" {
		if err := ensureControllerPKI(&cfg); err != nil {
			writeError(w, 500, "prepare controller PKI failed: "+err.Error())
			return
		}
		if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
			writeError(w, 500, "write controller PKI failed: "+err.Error())
			return
		}
		s.mu.Lock()
		s.cfg = cfg
		s.mu.Unlock()
	}
	plain, _, err := security.NewOpaqueToken("enroll_")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	expires := time.Now().Add(time.Duration(req.ExpiresMinutes) * time.Minute)
	admin := currentUser(r)
	var adminID int64
	if admin != nil {
		adminID = admin.ID
	}
	if err := s.getStore().CreateEnrollmentTokenWithSettings(r.Context(), plain, security.TokenPrefix(plain), 1, expires, adminID, settings); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "enrollment_token": plain, "expires_at": expires, "max_uses": 1, "mtls_address": cfg.Controller.PublicAddress})
}

func (s *Server) listEdgeNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.getStore().ListEdgeNodes(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(nodes))
	for _, node := range nodes {
		connected := false
		capabilities := json.RawMessage(node.CapabilitiesJSON)
		if s.controllerControl != nil {
			if online, live := s.controllerControl.NodeSession(node.NodeID); online {
				connected = true
				if len(live) > 0 {
					capabilities = live
				}
			}
		}
		var decoded map[string]any
		if json.Unmarshal(capabilities, &decoded) != nil {
			decoded = map[string]any{}
		}
		items = append(items, map[string]any{
			"node_id": node.NodeID, "name": node.Name, "status": node.Status,
			"last_seen_at": node.LastSeenAt, "last_remote_addr": node.LastRemoteAddr,
			"public_api_url": node.PublicAPIURL, "selectable": node.Selectable,
			"connected": connected, "capabilities": decoded,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": items})
}

func (s *Server) publicNodeDirectory(w http.ResponseWriter, r *http.Request) {
	store := s.getStore()
	cfg := s.getConfig()
	if store == nil || cfg.Mode != config.ModeController {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": []any{}})
		return
	}
	nodes, err := store.ListPublicEdgeNodes(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	items := make([]map[string]any, 0, len(nodes)+1)
	if controller := controllerDirectoryItem(cfg, r); controller != nil {
		items = append(items, controller)
	}
	for _, node := range nodes {
		online := false
		if s.controllerControl != nil {
			online, _ = s.controllerControl.NodeSession(node.NodeID)
		}
		items = append(items, map[string]any{"node_id": node.NodeID, "tag": node.Name, "api_url": node.PublicAPIURL, "online": online, "node_type": "edge"})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": items})
}

func controllerDirectoryItem(cfg config.Config, r *http.Request) map[string]any {
	controllerURL := strings.TrimRight(strings.TrimSpace(cfg.Node.PublicAPIURL), "/")
	if controllerURL == "" {
		controllerURL = externalRequestBaseURL(r)
	}
	controllerTag := strings.TrimSpace(cfg.Node.Tag)
	if controllerTag == "" {
		controllerTag = "中心节点"
	}
	if controllerURL == "" {
		return nil
	}
	return map[string]any{"node_id": "controller", "tag": controllerTag, "api_url": controllerURL, "online": true, "node_type": "controller"}
}

func (s *Server) deleteEdgeNode(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	if nodeID == "" || nodeID == "controller" {
		writeError(w, 400, "只能删除边缘节点，不能删除中心自身")
		return
	}
	store := s.getStore()
	if err := store.DeleteEdgeNode(r.Context(), nodeID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, 404, "节点不存在或已删除")
			return
		}
		writeError(w, 500, "删除节点失败："+err.Error())
		return
	}
	if s.controllerControl != nil {
		s.controllerControl.ForgetNode(nodeID)
	}
	if admin := currentUser(r); admin != nil {
		store.Audit(r.Context(), "admin", admin.ID, "delete_node", "node", nodeID, "registration, user grants and node telemetry removed")
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) updateEdgeNode(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Name         string `json:"name"`
		PublicAPIURL string `json:"public_api_url"`
		Selectable   bool   `json:"selectable"`
	}
	if nodeID == "" || readJSON(r, &req) != nil {
		writeError(w, http.StatusBadRequest, "invalid node settings")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.PublicAPIURL = strings.TrimRight(strings.TrimSpace(req.PublicAPIURL), "/")
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "node name is required")
		return
	}
	if req.Selectable {
		if err := validatePublicAPIURL(req.PublicAPIURL); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// Keep the legacy endpoint compatible, but never change just the catalog.
	capabilities, ok := s.edgeConfigurationCapabilities(w, r, nodeID, true)
	if !ok {
		return
	}
	var reported struct {
		Runtime *config.NodeRuntimeConfig `json:"runtime_settings"`
	}
	if json.Unmarshal(capabilities, &reported) != nil || reported.Runtime == nil {
		writeError(w, http.StatusConflict, "edge node has not reported its runtime settings")
		return
	}
	node := *reported.Runtime
	node.Tag, node.PublicAPIURL, node.Selectable = req.Name, req.PublicAPIURL, req.Selectable
	node = normalizeNodeRuntime(node)
	if err := validateNodeRuntime(node); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	payload, _ := json.Marshal(node)
	s.queueEdgeConfiguration(w, r, nodeID, "update_edge_runtime_settings", payload)
}

func (s *Server) updateEdgeRemotePermissions(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Reporting      config.EdgeReportingConfig      `json:"reporting"`
		RemoteCommands config.EdgeRemoteCommandsConfig `json:"remote_commands"`
	}
	if nodeID == "" || readJSON(r, &req) != nil {
		writeError(w, 400, "invalid edge permissions")
		return
	}
	if _, ok := s.edgeConfigurationCapabilities(w, r, nodeID, false); !ok {
		return
	}
	payload, _ := json.Marshal(req)
	s.queueEdgeConfiguration(w, r, nodeID, "update_edge_permissions", payload)
}

func (s *Server) updateEdgeRuntimeSettings(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	var req config.NodeRuntimeConfig
	if nodeID == "" || readJSON(r, &req) != nil {
		writeError(w, http.StatusBadRequest, "invalid edge runtime settings")
		return
	}
	req = normalizeNodeRuntime(req)
	if err := validateNodeRuntime(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, ok := s.edgeConfigurationCapabilities(w, r, nodeID, true); !ok {
		return
	}
	payload, _ := json.Marshal(req)
	s.queueEdgeConfiguration(w, r, nodeID, "update_edge_runtime_settings", payload)
}

func (s *Server) edgeConfigurationCapabilities(w http.ResponseWriter, r *http.Request, nodeID string, runtime bool) (json.RawMessage, bool) {
	node, err := s.getStore().GetEdgeNode(r.Context(), nodeID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
		} else {
			writeError(w, 500, err.Error())
		}
		return nil, false
	}
	capabilities := json.RawMessage(node.CapabilitiesJSON)
	if s.controllerControl != nil {
		if _, live := s.controllerControl.NodeSession(nodeID); len(live) > 0 {
			capabilities = live
		}
	}
	if !controllerAdministrationAllowed(capabilities) || (runtime && !runtimeSettingsAllowed(capabilities)) {
		writeError(w, http.StatusForbidden, "edge node has not enabled the required controller management permissions")
		return nil, false
	}
	return capabilities, true
}

// Ordinary configuration commands survive reconnects. An online response is
// successful only after the edge confirms persistence through its mTLS stream.
func (s *Server) queueEdgeConfiguration(w http.ResponseWriter, r *http.Request, nodeID, kind string, payload json.RawMessage) {
	// Monotonic desired-state versions fence late/offline command delivery.
	revision, err := s.getStore().NextIdentityRevision(r.Context())
	if err != nil {
		writeError(w, 500, "allocate configuration revision failed")
		return
	}
	var versioned map[string]json.RawMessage
	if err = json.Unmarshal(payload, &versioned); err != nil {
		writeError(w, 400, "invalid configuration payload")
		return
	}
	versioned["_configuration_revision"], _ = json.Marshal(revision)
	payload, _ = json.Marshal(versioned)
	commandID, _, err := security.NewOpaqueToken("cmd_")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	expiresAt := time.Now().Add(10 * time.Minute)
	command := cluster.NodeCommand{CommandID: commandID, NodeID: nodeID, Command: kind, Payload: payload, ExpiresAt: expiresAt}
	if err := s.getStore().CreateNodeCommand(r.Context(), db.NodeCommandRecord{CommandID: commandID, NodeID: nodeID, CommandType: command.Command, PayloadJSON: string(payload), ExpiresAt: expiresAt}); err != nil {
		writeError(w, 500, err.Error())
		return
	}
	delivered := false
	if s.controllerControl != nil {
		if online, _ := s.controllerControl.NodeSession(nodeID); online {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			result, sendErr := s.controllerControl.SendCommandAndWait(ctx, command)
			cancel()
			delivered = sendErr == nil || errors.Is(sendErr, context.DeadlineExceeded) || errors.Is(sendErr, context.Canceled)
			if delivered {
				_ = s.getStore().MarkNodeCommandDelivered(r.Context(), commandID)
			}
			if sendErr == nil {
				if result.Status != "succeeded" {
					writeError(w, http.StatusConflict, "edge rejected configuration: "+result.Error)
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"ok": true, "command_id": commandID, "delivered": true, "applied": true, "result": result.Result})
				return
			}
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "command_id": commandID, "delivered": delivered, "applied": false, "persistent": true, "expires_at": nil})
}

func (s *Server) rotateEdgeAdminCredentials(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Username           string `json:"username"`
		DisplayName        string `json:"display_name"`
		Password           string `json:"password"`
		ControllerPassword string `json:"controller_password"`
	}
	if nodeID == "" || readJSON(r, &req) != nil {
		writeError(w, 400, "invalid administrator credentials")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Username == "" || len(req.Username) > 64 {
		writeError(w, 400, "edge administrator username is invalid")
		return
	}
	if len(req.Password) < 8 || len([]byte(req.Password)) > 72 {
		writeError(w, 400, "edge administrator password must contain 8 to 72 bytes")
		return
	}
	admin := currentUser(r)
	if admin == nil || !security.CheckPassword(admin.PasswordHash, req.ControllerPassword) {
		writeError(w, http.StatusUnauthorized, "controller administrator password is incorrect")
		return
	}
	if s.controllerControl == nil {
		writeError(w, http.StatusConflict, "edge control endpoint is unavailable")
		return
	}
	online, capabilities := s.controllerControl.NodeSession(nodeID)
	if !online {
		writeError(w, http.StatusConflict, "edge node is offline; administrator credentials were not queued")
		return
	}
	if !controllerAdministrationAllowed(capabilities) {
		writeError(w, http.StatusForbidden, "edge node has not enabled controller administration")
		return
	}
	commandID, _, err := security.NewOpaqueToken("live_")
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	// This payload intentionally exists only in request/command memory. It is
	// never inserted into node_commands or included in audit details.
	payload, _ := json.Marshal(map[string]string{"username": req.Username, "display_name": req.DisplayName, "password": req.Password})
	command := cluster.NodeCommand{CommandID: commandID, NodeID: nodeID, Command: "rotate_edge_admin", Payload: payload, ExpiresAt: time.Now().Add(15 * time.Second)}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	result, err := s.controllerControl.SendCommandAndWait(ctx, command)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusGatewayTimeout, "edge node did not confirm the credential change")
		} else {
			writeError(w, http.StatusConflict, err.Error())
		}
		return
	}
	if result.Status != "succeeded" {
		writeError(w, http.StatusConflict, result.Error)
		return
	}
	s.getStore().Audit(r.Context(), "admin", admin.ID, "rotate_edge_admin_credentials", "edge_node", nodeID, "")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result.Result})
}

func controllerAdministrationAllowed(payload json.RawMessage) bool {
	var capabilities struct {
		Enabled bool `json:"controller_administration_enabled"`
	}
	return json.Unmarshal(payload, &capabilities) == nil && capabilities.Enabled
}

func runtimeSettingsAllowed(payload json.RawMessage) bool {
	var capabilities struct {
		RemoteCommands config.EdgeRemoteCommandsConfig `json:"remote_commands"`
	}
	return json.Unmarshal(payload, &capabilities) == nil && capabilities.RemoteCommands.ChangeRuntimeSettings
}

func (s *Server) createEdgeCommand(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Command string          `json:"command"`
		Scope   string          `json:"scope"`
		Payload json.RawMessage `json:"payload"`
	}
	if nodeID == "" || readJSON(r, &req) != nil {
		writeError(w, 400, "invalid command")
		return
	}
	switch req.Command {
	case "disconnect_client", "disconnect_connection", "block_ip", "unblock_ip":
	default:
		writeError(w, 400, "unsupported edge command")
		return
	}
	if req.Command == "disconnect_connection" {
		var p struct {
			ConnectionID string `json:"connection_id"`
		}
		if req.Scope == "global" || json.Unmarshal(req.Payload, &p) != nil || strings.TrimSpace(p.ConnectionID) == "" {
			writeError(w, 400, "invalid connection payload")
			return
		}
		p.ConnectionID = strings.TrimSpace(p.ConnectionID)
		req.Payload, _ = json.Marshal(p)
	}
	if req.Command == "block_ip" || req.Command == "unblock_ip" {
		var p struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(req.Payload, &p) != nil {
			writeError(w, 400, "invalid IP payload")
			return
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(p.IP))
		if err != nil {
			writeError(w, 400, "invalid IP address")
			return
		}
		p.IP = addr.Unmap().String()
		req.Payload, _ = json.Marshal(p)
		if req.Scope == "global" {
			if s.controllerControl != nil {
				unlock := s.controllerControl.LockIdentityMutation()
				defer unlock()
			}
			admin := currentUser(r)
			if req.Command == "block_ip" {
				_, err = s.getStore().UpsertBlockedInboundIP(r.Context(), p.IP, p.Reason, admin.ID)
			} else {
				err = s.getStore().DeleteBlockedInboundIP(r.Context(), p.IP)
			}
			if err != nil {
				writeError(w, 500, err.Error())
				return
			}
			if s.core != nil {
				if req.Command == "block_ip" {
					s.core.BlockInboundIP(p.IP, p.Reason)
				} else {
					s.core.UnblockInboundIP(p.IP)
				}
			}
			if s.controllerControl != nil {
				s.controllerControl.ScheduleBlockedIPPush()
			}
			writeJSON(w, 202, map[string]any{"ok": true, "scope": "global", "sync": "incremental; full baseline after reconnect"})
			return
		}
	}
	targets := []string{nodeID}
	waitForResult := req.Scope != "global" && (req.Command == "disconnect_client" || req.Command == "disconnect_connection")
	if waitForResult {
		if s.controllerControl == nil {
			writeError(w, 503, "中心控制通道不可用")
			return
		}
		if online, _ := s.controllerControl.NodeSession(nodeID); !online {
			writeError(w, 503, "边缘节点离线，无法执行踢出")
			return
		}
	}
	if req.Scope == "global" && s.controllerControl != nil {
		targets = s.controllerControl.ConnectedNodes()
	}
	created := []string{}
	for _, target := range targets {
		id, _, err := security.NewOpaqueToken("cmd_")
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		command := cluster.NodeCommand{CommandID: id, NodeID: target, Command: req.Command, Payload: req.Payload, ExpiresAt: time.Now().Add(5 * time.Minute)}
		if err := s.getStore().CreateNodeCommand(r.Context(), db.NodeCommandRecord{CommandID: id, NodeID: target, CommandType: req.Command, PayloadJSON: string(req.Payload), ExpiresAt: command.ExpiresAt}); err != nil {
			writeError(w, 500, err.Error())
			return
		}
		if waitForResult {
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			result, err := s.controllerControl.SendCommandAndWait(ctx, command)
			cancel()
			if err != nil {
				writeError(w, 504, "命令执行结果未确认，请刷新节点核对："+err.Error())
				return
			}
			encoded, _ := json.Marshal(result)
			if err := s.getStore().CompleteNodeCommand(r.Context(), target, id, result.Status, string(encoded)); err != nil {
				writeError(w, 500, err.Error())
				return
			}
			if result.Status != "succeeded" {
				writeError(w, 409, result.Error)
				return
			}
		} else if s.controllerControl != nil && s.controllerControl.SendCommand(command) {
			_ = s.getStore().MarkNodeCommandDelivered(r.Context(), id)
		}
		created = append(created, id)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "command_ids": created, "completed": waitForResult})
}

func (s *Server) listEdgeClients(w http.ResponseWriter, r *http.Request) {
	clients, err := s.getStore().ListEdgeClientPresence(r.Context(), strings.TrimSpace(r.URL.Query().Get("node_id")))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "clients": clients})
}

func (s *Server) listEdgeConnections(w http.ResponseWriter, r *http.Request) {
	connections, err := s.getStore().ListEdgeConnectionPresence(r.Context(), strings.TrimSpace(r.URL.Query().Get("node_id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "connections": connections})
}

func (s *Server) listEdgeTraffic(w http.ResponseWriter, r *http.Request) {
	traffic, err := s.getStore().ListEdgeNodeTraffic(r.Context(), strings.TrimSpace(r.URL.Query().Get("node_id")))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "traffic": traffic})
}

func (s *Server) listEdgeRuntimeLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	events, err := s.getStore().ListNodeEvents(r.Context(), strings.TrimSpace(r.URL.Query().Get("node_id")), "runtime_log", limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	logs := make([]map[string]any, 0, len(events))
	for _, event := range events {
		var payload any
		if json.Unmarshal([]byte(event.PayloadJSON), &payload) != nil {
			payload = map[string]any{"message": event.PayloadJSON}
		}
		logs = append(logs, map[string]any{
			"id": event.ID, "node_id": event.NodeID, "event_id": event.EventID,
			"payload": payload, "created_at": event.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "logs": logs})
}

// EdgeHeartbeatPayload applies the node administrator's reporting choices at
// send time, so changing the local settings does not require a process restart.
func (s *Server) EdgeHeartbeatPayload(ctx context.Context) cluster.HeartbeatPayload {
	if s.edgeState == nil {
		return cluster.HeartbeatPayload{}
	}
	payload := s.edgeState.HeartbeatPayload(ctx)
	payload.ReportingVersion = 1
	reporting := s.getConfig().Edge.Reporting
	if !reporting.ClientPresence {
		payload.Clients = nil
		payload.ClientsOnline = 0
	}
	payload.ConnectionsReportingEnabled = reporting.Connections
	if reporting.Connections && s.core != nil {
		connections := s.core.ListConnections(s.getConfig().UDPConnectionTTL)
		payload.FRPConnections = len(connections)
		payload.Connections = make([]cluster.EdgeConnectionSnapshot, 0, len(connections))
		for _, connection := range connections {
			payload.Connections = append(payload.Connections, cluster.EdgeConnectionSnapshot{
				ID: connection.ID, Protocol: connection.Protocol, UserID: connection.UserID, TokenID: connection.TokenID,
				ClientID: connection.ClientID, ClientAddr: connection.ClientAddr, LeaseID: connection.LeaseID,
				ProxyName: connection.ProxyName, ProxyType: connection.ProxyType, RemotePort: connection.RemotePort,
				InboundAddr: connection.InboundAddr, InboundIP: connection.InboundIP, InboundPort: connection.InboundPort,
				ServerAddr: connection.ServerAddr, OpenedAt: connection.OpenedAt, LastSeenAt: connection.LastSeenAt,
				CanTerminate: connection.CanTerminate,
			})
		}
	}
	if reporting.TrafficStatistics && s.core != nil {
		traffic := s.core.TrafficSnapshot()
		payload.Traffic = &cluster.EdgeTrafficSnapshot{
			BytesInbound: traffic.BytesInbound, BytesOutbound: traffic.BytesOutbound,
			SamplesInbound: traffic.SamplesInbound, SamplesOutbound: traffic.SamplesOutbound,
			StartedAt: traffic.StartedAt, CapturedAt: traffic.CapturedAt,
		}
	}
	return payload
}

func (s *Server) EdgePendingEvents(ctx context.Context) ([]cluster.EventEnvelope, error) {
	if s.edgeState == nil {
		return nil, nil
	}
	reporting := s.getConfig().Edge.Reporting
	types := []string{}
	if reporting.DPIEvents {
		types = append(types, "dpi_event")
	} else if err := s.edgeState.PruneDisabledDPIEvents(ctx); err != nil {
		return nil, err
	}
	if reporting.RuntimeLogs {
		types = append(types, "runtime_log")
	}
	return s.edgeState.PendingEventsForTypes(ctx, types)
}

func (s *Server) EdgeRuntimeLogsEnabled() bool {
	return s.getConfig().Mode == config.ModeEdge && s.getConfig().Edge.Reporting.RuntimeLogs
}

func (s *Server) EdgeDPIEventsEnabled() bool {
	return s.getConfig().Mode == config.ModeEdge && s.getConfig().Edge.Reporting.DPIEvents
}

// HandleObservedAddress migrates a loopback/unspecified automatic default to
// the public peer address observed by the Controller. Explicit administrator
// values (including domains) are never overwritten.
func (s *Server) HandleObservedAddress(address string) {
	address = strings.TrimSpace(address)
	if address == "" {
		return
	}
	cfg := s.getConfig()
	if cfg.Mode != config.ModeEdge || !isLocalAdvertiseAddress(cfg.Node.FRPAdvertiseAddr) {
		return
	}
	cfg.Node.FRPAdvertiseAddr = address
	syncLegacyFRPFields(&cfg)
	if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
		return
	}
	s.setRuntime(cfg, s.getStore())
	if s.edgeClient != nil {
		s.edgeClient.SetCapabilities(edgeCapabilities(cfg))
	}
}

func (s *Server) HandleEdgeCommand(ctx context.Context, command cluster.NodeCommand) cluster.CommandResult {
	result := cluster.CommandResult{CommandID: command.CommandID, Status: "failed"}
	if s.edgeState == nil {
		result.Error = "edge state unavailable"
		return result
	}
	if command.Command == "rotate_edge_admin" {
		return s.rotateLocalEdgeAdmin(ctx, command)
	}
	execute, cached, err := s.edgeState.BeginCommand(ctx, command)
	if err != nil {
		result.Error = err.Error()
		result.Status = "retry"
		return result
	}
	if !execute && cached != nil {
		return *cached
	}
	if superseded, err := s.edgeState.ConfigurationSuperseded(ctx, command.Command, command.Payload); err != nil {
		result.Status = "retry"
		result.Error = "read configuration revision: " + err.Error()
		return result
	} else if superseded {
		result.Status = "succeeded"
		result.Result = json.RawMessage(`{"superseded":true}`)
		if err := s.edgeState.FinishCommand(ctx, result); err != nil {
			result.Status = "retry"
			result.Error = err.Error()
		}
		return result
	}
	if command.Command != "update_edge_runtime_settings" && command.Command != "update_edge_permissions" && command.Command != "update_edge_advanced_settings" && !command.ExpiresAt.IsZero() && time.Now().After(command.ExpiresAt) {
		result.Error = "command expired before execution"
		_ = s.edgeState.FinishCommand(ctx, result)
		return result
	}
	cfg := s.getConfig()
	var output any
	switch command.Command {
	case "update_edge_permissions":
		if !cfg.Edge.ControllerAdministrationEnabled {
			result.Error = "controller administration is disabled on this edge"
			break
		}
		var p struct {
			Reporting      config.EdgeReportingConfig      `json:"reporting"`
			RemoteCommands config.EdgeRemoteCommandsConfig `json:"remote_commands"`
		}
		if json.Unmarshal(command.Payload, &p) != nil {
			result.Error = "invalid edge permissions payload"
			break
		}
		cfg.Edge.Reporting = p.Reporting
		cfg.Edge.RemoteCommands = p.RemoteCommands
		if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
			result.Error = "write edge config failed: " + err.Error()
			break
		}
		s.setRuntime(cfg, s.getStore())
		if s.edgeClient != nil {
			s.edgeClient.SetCapabilities(edgeCapabilities(cfg))
		}
		result.Status = "succeeded"
		output = map[string]any{"reporting": cfg.Edge.Reporting, "remote_commands": cfg.Edge.RemoteCommands}
	case "update_edge_runtime_settings":
		if !cfg.Edge.ControllerAdministrationEnabled || !cfg.Edge.RemoteCommands.ChangeRuntimeSettings {
			result.Error = "remote runtime settings are disabled on this edge"
			break
		}
		var node config.NodeRuntimeConfig
		if json.Unmarshal(command.Payload, &node) != nil {
			result.Error = "invalid edge runtime settings payload"
			break
		}
		node = normalizeNodeRuntime(node)
		if err := validateNodeRuntime(node); err != nil {
			result.Error = err.Error()
			break
		}
		restartRequired := cfg.Node.FRPBindPort != node.FRPBindPort
		cfg.Node = node
		syncLegacyFRPFields(&cfg)
		if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
			result.Error = "write edge config failed: " + err.Error()
			break
		}
		s.setRuntime(cfg, s.getStore())
		restartRequired = s.noteSettingsRestart(cfg, restartRequired)
		if s.edgeClient != nil {
			s.edgeClient.SetCapabilities(edgeCapabilities(cfg))
		}
		result.Status = "succeeded"
		output = map[string]any{"runtime_settings": cfg.Node, "restart_required": restartRequired}
	case "update_edge_advanced_settings":
		if !cfg.Edge.ControllerAdministrationEnabled || !cfg.Edge.RemoteCommands.ChangeRuntimeSettings {
			result.Error = "remote runtime settings are disabled on this edge"
			break
		}
		var advanced edgeAdvancedSettings
		if json.Unmarshal(command.Payload, &advanced) != nil {
			result.Error = "invalid edge advanced settings payload"
			break
		}
		oldCfg := cfg
		if err := applyEdgeAdvancedSettings(&cfg, advanced); err != nil {
			result.Error = err.Error()
			break
		}
		if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
			result.Error = "write edge config failed: " + err.Error()
			break
		}
		s.setRuntime(cfg, s.getStore())
		restartRequired := s.noteSettingsRestart(cfg, oldCfg.EmbeddedFRPEnabled != cfg.EmbeddedFRPEnabled ||
			oldCfg.FRPTransportTLS != cfg.FRPTransportTLS || oldCfg.FRPBindAddr != cfg.FRPBindAddr ||
			oldCfg.FRPProxyBindAddr != cfg.FRPProxyBindAddr || oldCfg.ConnectionTuning != cfg.ConnectionTuning)
		if s.edgeClient != nil {
			s.edgeClient.SetCapabilities(edgeCapabilities(cfg))
		}
		result.Status = "succeeded"
		output = map[string]any{"advanced_settings": edgeAdvancedSnapshot(cfg), "restart_required": restartRequired}
	case "disconnect_client":
		if !cfg.Edge.RemoteCommands.DisconnectClient {
			result.Error = "disconnect_client is disabled on this edge"
			break
		}
		var p struct {
			TokenID  int64  `json:"token_id"`
			ClientID string `json:"client_id"`
			Reason   string `json:"reason"`
		}
		if json.Unmarshal(command.Payload, &p) != nil || p.TokenID <= 0 || strings.TrimSpace(p.ClientID) == "" {
			result.Error = "invalid client payload"
			break
		}
		leases, err := s.edgeState.DisconnectClientForCommand(ctx, command.CommandID, p.TokenID, p.ClientID, p.Reason)
		if err != nil {
			result.Error = err.Error()
			break
		}
		terminated := 0
		if s.core != nil {
			for _, id := range leases {
				terminated += s.core.TerminateConnectionsForLease(id)
			}
		}
		output = map[string]any{"terminated_connections": terminated}
		result.Status = "succeeded"
	case "disconnect_connection":
		if !cfg.Edge.RemoteCommands.DisconnectConnection {
			result.Error = "disconnect_connection is disabled on this edge"
			break
		}
		var p struct {
			ConnectionID string `json:"connection_id"`
		}
		if json.Unmarshal(command.Payload, &p) != nil || strings.TrimSpace(p.ConnectionID) == "" {
			result.Error = "invalid connection payload"
			break
		}
		if s.core == nil || !s.core.TerminateTCPConnection(strings.TrimSpace(p.ConnectionID)) {
			result.Error = "connection is not active or cannot be terminated"
			break
		}
		output = map[string]any{"connection_id": strings.TrimSpace(p.ConnectionID), "terminated": true}
		result.Status = "succeeded"
	case "block_ip":
		if !cfg.Edge.RemoteCommands.BlockIP {
			result.Error = "block_ip is disabled on this edge"
			break
		}
		var p struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if json.Unmarshal(command.Payload, &p) != nil {
			result.Error = "invalid IP payload"
			break
		}
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(p.IP))
		if parseErr != nil {
			result.Error = "invalid IP address"
			break
		}
		p.IP = addr.String()
		if err := s.edgeState.UpsertBlockedIP(ctx, p.IP, p.Reason); err != nil {
			result.Error = err.Error()
			break
		}
		if s.core != nil {
			s.core.BlockInboundIP(p.IP, p.Reason)
		}
		output = map[string]any{"ip": p.IP}
		result.Status = "succeeded"
	case "unblock_ip":
		if !cfg.Edge.RemoteCommands.BlockIP {
			result.Error = "block_ip is disabled on this edge"
			break
		}
		var p struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(command.Payload, &p) != nil {
			result.Error = "invalid IP payload"
			break
		}
		addr, parseErr := netip.ParseAddr(strings.TrimSpace(p.IP))
		if parseErr != nil {
			result.Error = "invalid IP address"
			break
		}
		p.IP = addr.String()
		if err := s.edgeState.DeleteBlockedIP(ctx, p.IP); err != nil {
			result.Error = err.Error()
			break
		}
		if s.core != nil {
			s.core.UnblockInboundIP(p.IP)
			// Removing a node-local ban must not override the global scope.
			if blocks, err := s.edgeState.ListBlockedIPs(ctx); err == nil {
				for _, block := range blocks {
					if block.IP == p.IP {
						s.core.SetBlockedInboundIP(frpcore.BlockedInboundIP{IP: block.IP, Reason: block.Reason, CreatedAt: block.CreatedAt})
						break
					}
				}
			}
		}
		output = map[string]any{"ip": p.IP}
		result.Status = "succeeded"
	default:
		result.Error = "unsupported command"
	}
	if output != nil {
		result.Result, _ = json.Marshal(output)
	}
	if result.Status == "succeeded" {
		if err := s.edgeState.ConfirmConfiguration(ctx, command.Command, command.Payload); err != nil {
			result.Status = "retry"
			result.Error = "persist configuration revision: " + err.Error()
			return result
		}
	}
	if err := s.edgeState.FinishCommand(ctx, result); err != nil {
		result.Status = "retry"
		result.Error = "persist edge command result: " + err.Error()
	}
	return result
}

func (s *Server) rotateLocalEdgeAdmin(_ context.Context, command cluster.NodeCommand) cluster.CommandResult {
	result := cluster.CommandResult{CommandID: command.CommandID, Status: "failed"}
	cfg := s.getConfig()
	if !cfg.Edge.ControllerAdministrationEnabled {
		result.Error = "controller administration is disabled on this edge"
		return result
	}
	if !command.ExpiresAt.IsZero() && time.Now().After(command.ExpiresAt) {
		result.Error = "credential command expired before execution"
		return result
	}
	var p struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if json.Unmarshal(command.Payload, &p) != nil {
		result.Error = "invalid administrator credentials payload"
		return result
	}
	p.Username = strings.TrimSpace(p.Username)
	p.DisplayName = strings.TrimSpace(p.DisplayName)
	if p.Username == "" || len(p.Username) > 64 || len(p.Password) < 8 || len([]byte(p.Password)) > 72 {
		result.Error = "invalid administrator username or password"
		return result
	}
	hash, err := security.HashPassword(p.Password)
	p.Password = ""
	if err != nil {
		result.Error = "hash administrator password failed"
		return result
	}
	cfg.InitialAdmin = config.InitialAdminConfig{Username: p.Username, DisplayName: p.DisplayName, PasswordHash: hash}
	if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
		result.Error = "write edge config failed: " + err.Error()
		return result
	}
	s.setRuntime(cfg, s.getStore())
	if s.edgeClient != nil {
		s.edgeClient.SetCapabilities(edgeCapabilities(cfg))
	}
	result.Status = "succeeded"
	result.Result, _ = json.Marshal(map[string]string{"username": cfg.InitialAdmin.Username, "display_name": cfg.InitialAdmin.DisplayName})
	return result
}

func edgeCapabilities(cfg config.Config) map[string]any {
	return map[string]any{
		"reporting": cfg.Edge.Reporting, "remote_commands": cfg.Edge.RemoteCommands,
		"controller_administration_enabled": cfg.Edge.ControllerAdministrationEnabled,
		"admin_username":                    cfg.InitialAdmin.Username, "admin_display_name": cfg.InitialAdmin.DisplayName,
		"runtime_settings":  cfg.Node,
		"advanced_settings": edgeAdvancedSnapshot(cfg),
	}
}

func (s *Server) edgeStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if cfg.Mode != config.ModeEdge {
		writeError(w, http.StatusConflict, "edge mode is required")
		return
	}
	response := map[string]any{"ok": true, "node_id": cfg.Edge.NodeID, "node_name": cfg.Edge.NodeName, "controller_address": cfg.Edge.ControllerAddr, "controller_api_address": cfg.Edge.ControllerAPIAddr, "controller_connected": s.edgeClient != nil && s.edgeClient.Connected(), "reporting": cfg.Edge.Reporting, "remote_commands": cfg.Edge.RemoteCommands, "runtime_settings": cfg.Node}
	if certificate, err := edgeCertificate(cfg); err == nil {
		response["certificate_expires_at"] = certificate.NotAfter
		response["certificate_expired"] = time.Now().After(certificate.NotAfter)
		response["certificate_serial"] = certificate.SerialNumber.Text(16)
	} else {
		response["certificate_error"] = err.Error()
		response["certificate_expired"] = true
	}
	if s.edgeClient != nil && s.edgeClient.LastError() != "" {
		response["last_connection_error"] = s.edgeClient.LastError()
	}
	if s.edgeState != nil {
		if status, err := s.edgeState.Status(r.Context()); err == nil {
			response["state"] = status
		} else if !errors.Is(err, context.Canceled) {
			response["state_error"] = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) reEnrollEdge(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if cfg.Mode != config.ModeEdge || !cfg.Initialized {
		writeError(w, http.StatusConflict, "configured edge mode is required")
		return
	}
	var req struct {
		ControllerAddress string `json:"controller_address"`
		EnrollmentToken   string `json:"enrollment_token"`
		NodeName          string `json:"node_name"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	controllerAddress := cluster.NormalizeControllerAddress(req.ControllerAddress)
	if controllerAddress == "" {
		controllerAddress = cluster.NormalizeControllerAddress(cfg.Edge.ControllerAPIAddr)
	}
	nodeName := strings.TrimSpace(req.NodeName)
	if nodeName == "" {
		nodeName = cfg.Edge.NodeName
	}
	if controllerAddress == "" || nodeName == "" || strings.TrimSpace(req.EnrollmentToken) == "" {
		writeError(w, http.StatusBadRequest, "controller HTTPS address, node name and enrollment token are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	result, privateKey, err := cluster.EnrollEdgeAs(ctx, controllerAddress, nodeName, strings.TrimSpace(req.EnrollmentToken), cfg.Edge.NodeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg.Edge.NodeID = result.NodeID
	cfg.Edge.NodeName = nodeName
	cfg.Edge.ControllerAPIAddr = controllerAddress
	cfg.Edge.ControllerAddr = result.MTLSAddress
	cfg.Edge.ServerName = result.MTLSServerName
	cfg.Edge.TLS = config.TLSFiles{
		CACertificateBase64: config.EncodePEM([]byte(result.CACertificate)),
		CertificateBase64:   config.EncodePEM([]byte(result.Certificate)),
		PrivateKeyBase64:    config.EncodePEM(privateKey),
	}
	if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
		writeError(w, http.StatusInternalServerError, "write renewed edge certificate failed: "+err.Error())
		return
	}
	s.setRuntime(cfg, s.getStore())
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok": true, "node_id": result.NodeID, "certificate_expires_at": result.ExpiresAt,
		"restart_required": true,
	})
}

func edgeCertificate(cfg config.Config) (*x509.Certificate, error) {
	var certificatePEM []byte
	var err error
	if cfg.Edge.TLS.CertificateBase64 != "" {
		certificatePEM, err = config.DecodePEM(cfg.Edge.TLS.CertificateBase64)
	} else if cfg.Edge.TLS.CertFile != "" {
		certificatePEM, err = os.ReadFile(config.ResolvePath(cfg.ConfigPath, cfg.Edge.TLS.CertFile))
	} else {
		return nil, errors.New("edge certificate is not configured")
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid edge certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
