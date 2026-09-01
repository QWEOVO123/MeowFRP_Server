package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/security"
)

type adminLoginToken struct {
	Token     string `json:"admin_token"`
	ExpiresAt string `json:"expires_at"`
	ExpiresIn int64  `json:"expires_in"`
}

func (s *Server) bootstrapState(w http.ResponseWriter, r *http.Request) {
	store := s.getStore()
	cfg := s.getConfig()
	if cfg.ConfigState == "unconfigured" || cfg.ConfigState == "invalid" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "initialized": false, "setup_required": true, "database_ready": false, "database_error": false, "repair_required": false, "config_state": cfg.ConfigState, "config_error": cfg.ConfigError, "mode": "", "config_path": cfg.ConfigPath})
		return
	}
	if cfg.Mode == config.ModeEdge {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "initialized": cfg.Initialized, "setup_required": !cfg.Initialized, "database_ready": s.edgeState != nil, "database_error": false, "repair_required": false, "config_state": cfg.ConfigState, "mode": cfg.Mode, "config_path": cfg.ConfigPath})
		return
	}
	if store == nil {
		initialized := cfg.Initialized
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":              true,
			"initialized":     initialized,
			"setup_required":  !initialized,
			"database_ready":  false,
			"database_error":  initialized,
			"repair_required": initialized,
			"config_path":     cfg.ConfigPath,
		})
		return
	}
	dbInitialized, err := store.IsInitialized(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	initialized := cfg.Initialized || dbInitialized
	if dbInitialized && !cfg.Initialized {
		cfg.Initialized = true
		_ = config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig())
		s.setRuntime(cfg, store)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"initialized":     initialized,
		"setup_required":  !initialized,
		"database_ready":  true,
		"database_error":  false,
		"repair_required": false,
		"config_path":     cfg.ConfigPath,
	})
}

type setupAdminRequest struct {
	Username    string               `json:"username"`
	Password    string               `json:"password"`
	DisplayName string               `json:"display_name"`
	Database    config.DatabaseSetup `json:"database"`
}

type repairDatabaseRequest struct {
	Username string               `json:"username"`
	Password string               `json:"password"`
	Database config.DatabaseSetup `json:"database"`
}

func (s *Server) setupAdmin(w http.ResponseWriter, r *http.Request) {
	var req setupAdminRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if err := validateAdminPassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := security.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	cfg := s.getConfig()
	if cfg.Initialized {
		writeError(w, http.StatusConflict, "system already initialized")
		return
	}
	if cfg.ConfigState == "invalid" {
		if _, err := config.PreserveInvalidFile(cfg.ConfigPath); err != nil {
			writeError(w, 500, "preserve invalid config failed: "+err.Error())
			return
		}
	}
	cfg.Mode = config.ModeController
	cfg.ConfigVersion = 2
	cfg.ConfigState = "configured"
	cfg.ConfigError = ""
	initializeNodeRuntimeFromRequest(&cfg, r, "中心节点")
	store := s.getStore()
	if needsDatabaseSetup(store, req.Database) {
		if err := validateDatabaseSetup(req.Database); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		dsn := config.DSNFromDatabaseSetup(req.Database)
		newStore, err := db.Open(dsn)
		if err != nil {
			writeError(w, http.StatusBadRequest, "database connection failed: "+err.Error())
			return
		}
		if err := newStore.Migrate(r.Context()); err != nil {
			_ = newStore.Close()
			writeError(w, http.StatusBadRequest, "database migration failed: "+err.Error())
			return
		}
		cfg.MySQLDSN = dsn
		if cfg.CookieSecret == "" || cfg.CookieSecret == "dev-change-me-before-production" {
			secret, err := config.RandomSecret()
			if err != nil {
				_ = newStore.Close()
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			cfg.CookieSecret = secret
		}
		fileCfg := cfg.FileConfig()
		if err := config.WriteFileConfig(cfg.ConfigPath, fileCfg); err != nil {
			_ = newStore.Close()
			writeError(w, http.StatusInternalServerError, "write config failed: "+err.Error())
			return
		}
		s.setRuntime(cfg, newStore)
		store = newStore
	}

	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "database setup is required")
		return
	}
	initialized, err := store.IsInitialized(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if initialized {
		writeError(w, http.StatusConflict, "system already initialized")
		return
	}

	user, err := store.CreateInitialAdmin(r.Context(), req.Username, req.DisplayName, hash)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg.Initialized = true
	cfg.InitialAdmin = config.InitialAdminConfig{
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		PasswordHash: hash,
	}
	if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
		writeError(w, http.StatusInternalServerError, "write config failed: "+err.Error())
		return
	}
	s.setRuntime(cfg, store)
	store.Audit(r.Context(), "system", 0, "setup_admin", "user", req.Username, "initial administrator created")
	loginToken, err := s.issueAdminBrowserToken(r, w, user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":               true,
		"user":             user,
		"admin_token":      loginToken.Token,
		"expires_at":       loginToken.ExpiresAt,
		"expires_in":       loginToken.ExpiresIn,
		"config_path":      cfg.ConfigPath,
		"restart_required": true,
	})
}

func (s *Server) repairDatabase(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	if !cfg.Initialized {
		writeError(w, http.StatusConflict, "system is not initialized")
		return
	}
	if cfg.InitialAdmin.Username == "" || cfg.InitialAdmin.PasswordHash == "" {
		writeError(w, http.StatusForbidden, "initial admin credential is not available in cfg")
		return
	}
	var req repairDatabaseRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username != cfg.InitialAdmin.Username || !security.CheckPassword(cfg.InitialAdmin.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid initial admin credential")
		return
	}
	if err := validateDatabaseSetup(req.Database); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dsn := config.DSNFromDatabaseSetup(req.Database)
	newStore, err := db.Open(dsn)
	if err != nil {
		writeError(w, http.StatusBadRequest, "database connection failed: "+err.Error())
		return
	}
	if err := newStore.Migrate(r.Context()); err != nil {
		_ = newStore.Close()
		writeError(w, http.StatusBadRequest, "database migration failed: "+err.Error())
		return
	}
	dbInitialized, err := newStore.IsInitialized(r.Context())
	if err != nil {
		_ = newStore.Close()
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !dbInitialized {
		if _, err := newStore.CreateInitialAdmin(r.Context(), cfg.InitialAdmin.Username, cfg.InitialAdmin.DisplayName, cfg.InitialAdmin.PasswordHash); err != nil {
			_ = newStore.Close()
			writeError(w, http.StatusBadRequest, "create initial admin in repaired database failed: "+err.Error())
			return
		}
	}
	cfg.MySQLDSN = dsn
	cfg.Initialized = true
	if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
		_ = newStore.Close()
		writeError(w, http.StatusInternalServerError, "write config failed: "+err.Error())
		return
	}
	s.setRuntime(cfg, newStore)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"database_ready":   true,
		"config_path":      cfg.ConfigPath,
		"restart_required": false,
	})
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := s.getConfig()
	if cfg.Mode == config.ModeEdge {
		if strings.TrimSpace(req.Username) != cfg.InitialAdmin.Username || !security.CheckPassword(cfg.InitialAdmin.PasswordHash, req.Password) {
			writeError(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
		user := &db.User{ID: 1, Username: cfg.InitialAdmin.Username, DisplayName: cfg.InitialAdmin.DisplayName, Role: "admin", Status: "active"}
		loginToken, err := s.issueEdgeAdminBrowserToken(w, user)
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": user, "admin_token": loginToken.Token, "expires_at": loginToken.ExpiresAt, "expires_in": loginToken.ExpiresIn})
		return
	}
	store := s.getStore()
	if store == nil {
		writeError(w, http.StatusServiceUnavailable, "system setup required")
		return
	}
	user, err := store.GetUserByUsername(r.Context(), strings.TrimSpace(req.Username))
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !security.CheckPassword(user.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if user.Role != "admin" || user.Status != "active" {
		writeError(w, http.StatusForbidden, "admin account is not active")
		return
	}
	loginToken, err := s.issueAdminBrowserToken(r, w, user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	store.Audit(r.Context(), "admin", user.ID, "login", "user", req.Username, "admin logged in")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"user":        user,
		"admin_token": loginToken.Token,
		"expires_at":  loginToken.ExpiresAt,
		"expires_in":  loginToken.ExpiresIn,
	})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	clearAdminTokenCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user": currentUser(r)})
}

func needsDatabaseSetup(store *db.Store, database config.DatabaseSetup) bool {
	return store == nil || database.Host != "" || database.Database != "" || database.Username != ""
}

func validateDatabaseSetup(database config.DatabaseSetup) error {
	if strings.TrimSpace(database.Host) == "" {
		return errors.New("database host is required")
	}
	if strings.TrimSpace(database.Username) == "" {
		return errors.New("database username is required")
	}
	if strings.TrimSpace(database.Database) == "" {
		return errors.New("database name is required")
	}
	return nil
}

func (s *Server) getSystemSettings(w http.ResponseWriter, r *http.Request) {
	cfg := s.getConfig()
	nodeSettings := cfg.Node
	if strings.TrimSpace(nodeSettings.Tag) == "" {
		if cfg.Mode == config.ModeEdge && strings.TrimSpace(cfg.Edge.NodeName) != "" {
			nodeSettings.Tag = cfg.Edge.NodeName
		} else {
			nodeSettings.Tag = "中心节点"
		}
	}
	if strings.TrimSpace(nodeSettings.PublicAPIURL) == "" {
		nodeSettings.PublicAPIURL = externalRequestBaseURL(r)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"settings": map[string]any{
			"mode":                  cfg.Mode,
			"embedded_frps_enabled": cfg.EmbeddedFRPEnabled,
			"frp_bind_addr":         cfg.FRPBindAddr,
			"frp_proxy_bind_addr":   cfg.FRPProxyBindAddr,
			"frp_server_addr":       cfg.FRPServerAddr,
			"frp_server_port":       cfg.FRPServerPort,
			"frp_transport_tls":     cfg.FRPTransportTLS,
			"client_config_comment": cfg.ClientConfigComment,
			"session_ttl":           cfg.SessionTTL.String(),
			"udp_connection_ttl":    cfg.UDPConnectionTTL.String(),
			"config_path":           cfg.ConfigPath,
			"node":                  nodeSettings,
			"controller":            map[string]any{"edge_access_enabled": cfg.Controller.EdgeAccessEnabled, "listen_addr": cfg.Controller.ListenAddr, "public_address": cfg.Controller.PublicAddress, "heartbeat_interval_seconds": cfg.Controller.HeartbeatIntervalSeconds, "pki_configured": cfg.Controller.TLS.CACertificateBase64 != "" || cfg.Controller.TLS.CAFile != ""},
			"edge":                  map[string]any{"node_id": cfg.Edge.NodeID, "node_name": cfg.Edge.NodeName, "controller_address": cfg.Edge.ControllerAddr, "server_name": cfg.Edge.ServerName, "state_path": cfg.Edge.StatePath, "controller_administration_enabled": cfg.Edge.ControllerAdministrationEnabled, "reporting": cfg.Edge.Reporting, "remote_commands": cfg.Edge.RemoteCommands, "mtls_configured": cfg.Edge.TLS.CACertificateBase64 != "" || cfg.Edge.TLS.CAFile != ""},
		},
	})
}

type updateSystemSettingsRequest struct {
	EmbeddedFRPEnabled              *bool                            `json:"embedded_frps_enabled"`
	FRPBindAddr                     string                           `json:"frp_bind_addr"`
	FRPProxyBindAddr                string                           `json:"frp_proxy_bind_addr"`
	FRPServerAddr                   string                           `json:"frp_server_addr"`
	FRPServerPort                   int                              `json:"frp_server_port"`
	FRPTransportTLS                 bool                             `json:"frp_transport_tls"`
	ClientConfigComment             string                           `json:"client_config_comment"`
	SessionTTL                      string                           `json:"session_ttl"`
	UDPConnectionTTL                string                           `json:"udp_connection_ttl"`
	Controller                      *config.ControllerConfig         `json:"controller,omitempty"`
	Node                            *config.NodeRuntimeConfig        `json:"node,omitempty"`
	Reporting                       *config.EdgeReportingConfig      `json:"reporting,omitempty"`
	RemoteCommands                  *config.EdgeRemoteCommandsConfig `json:"remote_commands,omitempty"`
	ControllerAdministrationEnabled *bool                            `json:"controller_administration_enabled,omitempty"`
}

func (s *Server) updateSystemSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSystemSettingsRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := s.getConfig()
	oldCfg := cfg
	if cfg.Mode == config.ModeEdge {
		if req.Node != nil {
			node := normalizeNodeRuntime(*req.Node)
			if err := validateNodeRuntime(node); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			cfg.Node = node
			syncLegacyFRPFields(&cfg)
		}
		if req.Reporting != nil {
			cfg.Edge.Reporting = *req.Reporting
		}
		if req.RemoteCommands != nil {
			cfg.Edge.RemoteCommands = *req.RemoteCommands
		}
		if req.ControllerAdministrationEnabled != nil {
			cfg.Edge.ControllerAdministrationEnabled = *req.ControllerAdministrationEnabled
		}
		if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
			writeError(w, 500, "write config failed: "+err.Error())
			return
		}
		s.setRuntime(cfg, s.getStore())
		if s.edgeClient != nil {
			s.edgeClient.SetCapabilities(edgeCapabilities(cfg))
		}
		restartRequired := oldCfg.Node.FRPBindPort != cfg.Node.FRPBindPort
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": restartRequired})
		return
	}
	if req.Node != nil {
		node := normalizeNodeRuntime(*req.Node)
		if err := validateNodeRuntime(node); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		cfg.Node = node
		syncLegacyFRPFields(&cfg)
	} else {
		// Accept the legacy settings request during rolling upgrades.
		cfg.Node.FRPAdvertiseAddr = strings.TrimSpace(req.FRPServerAddr)
		cfg.Node.FRPBindPort = req.FRPServerPort
		syncLegacyFRPFields(&cfg)
	}
	req.FRPServerAddr = strings.TrimSpace(req.FRPServerAddr)
	req.FRPBindAddr = strings.TrimSpace(req.FRPBindAddr)
	req.FRPProxyBindAddr = strings.TrimSpace(req.FRPProxyBindAddr)
	req.ClientConfigComment = strings.TrimSpace(req.ClientConfigComment)
	req.SessionTTL = strings.TrimSpace(req.SessionTTL)
	req.UDPConnectionTTL = strings.TrimSpace(req.UDPConnectionTTL)
	if cfg.FRPServerAddr == "" {
		writeError(w, http.StatusBadRequest, "frp_server_addr is required")
		return
	}
	if cfg.FRPServerPort <= 0 || cfg.FRPServerPort > 65535 {
		writeError(w, http.StatusBadRequest, "frp_server_port is invalid")
		return
	}
	var sessionTTL = s.getConfig().SessionTTL
	var udpConnectionTTL = s.getConfig().UDPConnectionTTL
	if req.SessionTTL != "" {
		parsed, err := config.ParseDuration(req.SessionTTL)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "session_ttl is invalid")
			return
		}
		sessionTTL = parsed
	}
	if req.UDPConnectionTTL != "" {
		parsed, err := config.ParseDuration(req.UDPConnectionTTL)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "udp_connection_ttl is invalid")
			return
		}
		udpConnectionTTL = parsed
	}
	if req.EmbeddedFRPEnabled != nil {
		cfg.EmbeddedFRPEnabled = *req.EmbeddedFRPEnabled
	}
	if req.FRPBindAddr != "" {
		cfg.FRPBindAddr = req.FRPBindAddr
	}
	if req.FRPProxyBindAddr != "" {
		cfg.FRPProxyBindAddr = req.FRPProxyBindAddr
	}
	// FRPServerAddr/FRPServerPort were synchronized from cfg.Node above.
	cfg.FRPTransportTLS = req.FRPTransportTLS
	cfg.SessionTTL = sessionTTL
	cfg.UDPConnectionTTL = udpConnectionTTL
	if req.ClientConfigComment != "" {
		cfg.ClientConfigComment = req.ClientConfigComment
	}
	if req.Controller != nil {
		cfg.Controller.EdgeAccessEnabled = req.Controller.EdgeAccessEnabled
		if strings.TrimSpace(req.Controller.ListenAddr) != "" {
			cfg.Controller.ListenAddr = strings.TrimSpace(req.Controller.ListenAddr)
		}
		if strings.TrimSpace(req.Controller.PublicAddress) != "" {
			cfg.Controller.PublicAddress = cluster.NormalizeControllerAddress(req.Controller.PublicAddress)
		}
		if req.Controller.HeartbeatIntervalSeconds != 0 {
			if req.Controller.HeartbeatIntervalSeconds < 2 || req.Controller.HeartbeatIntervalSeconds > 60 {
				writeError(w, 400, "heartbeat interval must be between 2 and 60 seconds")
				return
			}
			cfg.Controller.HeartbeatIntervalSeconds = req.Controller.HeartbeatIntervalSeconds
		}
		if cfg.Controller.EdgeAccessEnabled {
			if cfg.Controller.PublicAddress == "" {
				writeError(w, http.StatusBadRequest, "controller public_address is required when edge access is enabled")
				return
			}
			if err := ensureControllerPKI(&cfg); err != nil {
				writeError(w, 500, "prepare controller PKI failed: "+err.Error())
				return
			}
		}
	}
	if s.controllerControl != nil {
		s.controllerControl.SetHeartbeatInterval(cfg.Controller.HeartbeatIntervalSeconds)
	}
	if err := config.WriteFileConfig(cfg.ConfigPath, cfg.FileConfig()); err != nil {
		writeError(w, http.StatusInternalServerError, "write config failed: "+err.Error())
		return
	}
	s.setRuntime(cfg, s.getStore())
	admin := currentUser(r)
	if admin != nil {
		s.getStore().Audit(r.Context(), "admin", admin.ID, "update_system_settings", "system", "frp", "")
	}
	restartRequired := oldCfg.EmbeddedFRPEnabled != cfg.EmbeddedFRPEnabled ||
		oldCfg.FRPBindAddr != cfg.FRPBindAddr ||
		oldCfg.FRPProxyBindAddr != cfg.FRPProxyBindAddr ||
		oldCfg.FRPServerPort != cfg.FRPServerPort ||
		oldCfg.FRPTransportTLS != cfg.FRPTransportTLS || oldCfg.Controller.EdgeAccessEnabled != cfg.Controller.EdgeAccessEnabled || oldCfg.Controller.ListenAddr != cfg.Controller.ListenAddr
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": restartRequired})
}

func (s *Server) issueEdgeAdminBrowserToken(w http.ResponseWriter, user *db.User) (adminLoginToken, error) {
	cfg := s.getConfig()
	token, expiresAt, err := security.NewAdminBrowserToken(user.ID, cfg.InitialAdmin.PasswordHash, cfg.CookieSecret, cfg.SessionTTL)
	if err != nil {
		return adminLoginToken{}, err
	}
	setAdminTokenCookie(w, token, expiresAt)
	return adminLoginToken{Token: token, ExpiresAt: expiresAt.Format(time.RFC3339), ExpiresIn: int64(cfg.SessionTTL.Seconds())}, nil
}

func (s *Server) issueAdminBrowserToken(r *http.Request, w http.ResponseWriter, user *db.User) (adminLoginToken, error) {
	adminToken, err := s.ensureAdminFixedToken(r, user.ID)
	if err != nil {
		return adminLoginToken{}, err
	}
	cfg := s.getConfig()
	token, expiresAt, err := security.NewAdminBrowserToken(user.ID, adminToken.TokenHash, cfg.CookieSecret, cfg.SessionTTL)
	if err != nil {
		return adminLoginToken{}, err
	}
	setAdminTokenCookie(w, token, expiresAt)
	return adminLoginToken{
		Token:     token,
		ExpiresAt: expiresAt.Format("2006-01-02T15:04:05Z07:00"),
		ExpiresIn: int64(cfg.SessionTTL.Seconds()),
	}, nil
}

func (s *Server) ensureAdminFixedToken(r *http.Request, userID int64) (*db.AdminAPIToken, error) {
	adminToken, err := s.store.GetAdminAPITokenByUserID(r.Context(), userID)
	if err == nil && adminToken.Status == "active" {
		return adminToken, nil
	}
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		return nil, err
	}
	plain, hash, err := security.NewOpaqueToken("adm_")
	if err != nil {
		return nil, err
	}
	return s.store.CreateAdminAPIToken(r.Context(), userID, hash, security.TokenPrefix(plain))
}
