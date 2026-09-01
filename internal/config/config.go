package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const (
	ModeController = "controller"
	ModeEdge       = "edge"
)

type Config struct {
	ConfigPath          string
	ConfigVersion       int
	Mode                string
	ConfigState         string
	ConfigError         string
	HTTPAddr            string
	MySQLDSN            string
	CookieSecret        string
	SessionTTL          time.Duration
	RuntimeTokenTTL     time.Duration
	UDPConnectionTTL    time.Duration
	EmbeddedFRPEnabled  bool
	FRPBindAddr         string
	FRPProxyBindAddr    string
	FRPServerAddr       string
	FRPServerPort       int
	FRPTransportTLS     bool
	ClientConfigComment string
	InitialAdmin        InitialAdminConfig
	Controller          ControllerConfig
	Edge                EdgeConfig
	Node                NodeRuntimeConfig
	Initialized         bool
}

// NodeRuntimeConfig describes the public endpoint and the server-side port
// pool of this process, regardless of whether it runs as Controller or Edge.
// The legacy FRPServerAddr/FRPServerPort fields are kept in sync for backward
// compatibility with existing cfg files and API consumers.
type NodeRuntimeConfig struct {
	Tag              string `json:"tag"`
	PublicAPIURL     string `json:"public_api_url"`
	FRPAdvertiseAddr string `json:"frp_advertise_addr"`
	FRPBindPort      int    `json:"frp_bind_port"`
	PortRangeStart   int    `json:"port_range_start"`
	PortRangeEnd     int    `json:"port_range_end"`
	Selectable       bool   `json:"selectable"`
}

type ControllerConfig struct {
	EdgeAccessEnabled        bool     `json:"edge_access_enabled"`
	ListenAddr               string   `json:"listen_addr"`
	PublicAddress            string   `json:"public_address"`
	TLS                      TLSFiles `json:"tls"`
	CAKeyFile                string   `json:"ca_key_file"`
	HeartbeatIntervalSeconds int      `json:"heartbeat_interval_seconds"`
}

type TLSFiles struct {
	CAFile              string `json:"ca_file"`
	CertFile            string `json:"cert_file"`
	KeyFile             string `json:"key_file"`
	CACertificateBase64 string `json:"ca_certificate_base64,omitempty"`
	CAPrivateKeyBase64  string `json:"ca_private_key_base64,omitempty"`
	CertificateBase64   string `json:"certificate_base64,omitempty"`
	PrivateKeyBase64    string `json:"private_key_base64,omitempty"`
}

type EdgeReportingConfig struct {
	ClientPresence    bool `json:"client_presence"`
	Connections       bool `json:"connections"`
	TrafficStatistics bool `json:"traffic_statistics"`
	DPIEvents         bool `json:"dpi_events"`
	RuntimeLogs       bool `json:"runtime_logs"`
}

type EdgeRemoteCommandsConfig struct {
	DisconnectClient      bool `json:"disconnect_client"`
	DisconnectConnection  bool `json:"disconnect_connection"`
	BlockIP               bool `json:"block_ip"`
	ChangeRuntimeSettings bool `json:"change_runtime_settings"`
}

type EdgeConfig struct {
	NodeID                          string                   `json:"node_id"`
	NodeName                        string                   `json:"node_name"`
	ControllerAddr                  string                   `json:"controller_address"`
	ControllerAPIAddr               string                   `json:"controller_api_address,omitempty"`
	ServerName                      string                   `json:"server_name"`
	TLS                             TLSFiles                 `json:"tls"`
	StatePath                       string                   `json:"state_path"`
	ControllerAdministrationEnabled bool                     `json:"controller_administration_enabled"`
	Reporting                       EdgeReportingConfig      `json:"reporting"`
	RemoteCommands                  EdgeRemoteCommandsConfig `json:"remote_commands"`
}

type InitialAdminConfig struct {
	Username     string `json:"username"`
	DisplayName  string `json:"display_name"`
	PasswordHash string `json:"password_hash"`
}

type FileConfig struct {
	ConfigVersion       int                `json:"config_version,omitempty"`
	Mode                string             `json:"mode,omitempty"`
	MySQLDSN            string             `json:"mysql_dsn"`
	CookieSecret        string             `json:"cookie_secret"`
	SessionTTL          string             `json:"session_ttl"`
	RuntimeTokenTTL     string             `json:"runtime_token_ttl"`
	UDPConnectionTTL    string             `json:"udp_connection_ttl"`
	EmbeddedFRPEnabled  *bool              `json:"embedded_frps_enabled,omitempty"`
	FRPBindAddr         string             `json:"frp_bind_addr"`
	FRPProxyBindAddr    string             `json:"frp_proxy_bind_addr"`
	FRPServerAddr       string             `json:"frp_server_addr"`
	FRPServerPort       int                `json:"frp_server_port"`
	FRPTransportTLS     bool               `json:"frp_transport_tls"`
	ClientConfigComment string             `json:"client_config_comment"`
	InitialAdmin        InitialAdminConfig `json:"initial_admin"`
	Controller          ControllerConfig   `json:"controller"`
	Edge                EdgeConfig         `json:"edge"`
	Node                NodeRuntimeConfig  `json:"node"`
	Initialized         bool               `json:"initialized"`
	CreatedAt           time.Time          `json:"created_at"`
}

type DatabaseSetup struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
}

func Load() (Config, error) {
	cfg := defaults()
	cfg.ConfigPath = env("FRP_CONTROL_CONFIG", defaultConfigPath())

	if fileCfg, err := ReadFileConfig(cfg.ConfigPath); err == nil {
		applyFileConfig(&cfg, fileCfg)
		if err := Validate(cfg); err != nil {
			cfg.ConfigState = "invalid"
			cfg.ConfigError = err.Error()
			cfg.Initialized = false
			return cfg, nil
		}
		cfg.ConfigState = "configured"
	} else if errors.Is(err, os.ErrNotExist) {
		cfg.ConfigState = "unconfigured"
	} else if !os.IsNotExist(err) {
		cfg.ConfigState = "invalid"
		cfg.ConfigError = err.Error()
		cfg.Initialized = false
		return cfg, nil
	}

	applyEnv(&cfg)
	return cfg, nil
}

func defaults() Config {
	return Config{
		ConfigVersion:       2,
		HTTPAddr:            env("FRP_CONTROL_HTTP_ADDR", ":8080"),
		CookieSecret:        env("FRP_CONTROL_COOKIE_SECRET", "dev-change-me-before-production"),
		SessionTTL:          envDuration("FRP_CONTROL_SESSION_TTL", time.Hour),
		RuntimeTokenTTL:     envDuration("FRP_CONTROL_RUNTIME_TOKEN_TTL", 24*time.Hour),
		UDPConnectionTTL:    envDuration("FRP_CONTROL_UDP_CONNECTION_TTL", 10*time.Second),
		EmbeddedFRPEnabled:  envBool("FRP_CONTROL_EMBEDDED_FRPS_ENABLED", true),
		FRPBindAddr:         env("FRP_CONTROL_FRP_BIND_ADDR", "0.0.0.0"),
		FRPProxyBindAddr:    env("FRP_CONTROL_FRP_PROXY_BIND_ADDR", "0.0.0.0"),
		FRPServerAddr:       env("FRP_CONTROL_FRP_SERVER_ADDR", "127.0.0.1"),
		FRPServerPort:       envInt("FRP_CONTROL_FRP_SERVER_PORT", 7000),
		FRPTransportTLS:     envBool("FRP_CONTROL_FRP_TRANSPORT_TLS", false),
		ClientConfigComment: env("FRP_CONTROL_CLIENT_CONFIG_COMMENT", "generated by frp-control-server"),
		Controller: ControllerConfig{
			ListenAddr: "0.0.0.0:9443", HeartbeatIntervalSeconds: 5,
		},
		Edge: EdgeConfig{
			StatePath: "data/edge-state.db",
			Reporting: EdgeReportingConfig{ClientPresence: true},
			RemoteCommands: EdgeRemoteCommandsConfig{
				DisconnectClient:     true,
				DisconnectConnection: true,
			},
		},
		Node: NodeRuntimeConfig{FRPBindPort: 7000, PortRangeStart: 1024, PortRangeEnd: 65535, Selectable: true},
	}
}

func ReadFileConfig(path string) (FileConfig, error) {
	var cfg FileConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func WriteFileConfig(path string, cfg FileConfig) error {
	if cfg.ConfigVersion == 0 {
		cfg.ConfigVersion = 2
	}
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = time.Now()
	}
	if cfg.CookieSecret == "" {
		secret, err := RandomSecret()
		if err != nil {
			return err
		}
		cfg.CookieSecret = secret
	}
	if cfg.SessionTTL == "" {
		cfg.SessionTTL = "1h"
	}
	if cfg.RuntimeTokenTTL == "" {
		cfg.RuntimeTokenTTL = "24h"
	}
	if cfg.UDPConnectionTTL == "" {
		cfg.UDPConnectionTTL = "10s"
	}
	if cfg.EmbeddedFRPEnabled == nil {
		enabled := true
		cfg.EmbeddedFRPEnabled = &enabled
	}
	if cfg.ClientConfigComment == "" {
		cfg.ClientConfigComment = "generated by frp-control-server"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tempPath := path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		if _, statErr := os.Stat(path); statErr != nil {
			_ = os.Remove(tempPath)
			return err
		}
		backupPath := path + ".bak"
		_ = os.Remove(backupPath)
		if backupErr := os.Rename(path, backupPath); backupErr != nil {
			_ = os.Remove(tempPath)
			return err
		}
		if replaceErr := os.Rename(tempPath, path); replaceErr != nil {
			_ = os.Rename(backupPath, path)
			return replaceErr
		}
		_ = os.Remove(backupPath)
	}
	return nil
}

func PreserveInvalidFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	backup := fmt.Sprintf("%s.invalid-%s", path, time.Now().Format("20060102-150405"))
	if err := os.WriteFile(backup, data, 0o600); err != nil {
		return "", err
	}
	return backup, nil
}

func DSNFromDatabaseSetup(db DatabaseSetup) string {
	port := db.Port
	if port == 0 {
		port = 3306
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&multiStatements=true&charset=utf8mb4,utf8",
		db.Username, db.Password, db.Host, port, db.Database)
}

func RandomSecret() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (c Config) FileConfig() FileConfig {
	return FileConfig{
		ConfigVersion:       c.ConfigVersion,
		Mode:                c.Mode,
		MySQLDSN:            c.MySQLDSN,
		CookieSecret:        c.CookieSecret,
		SessionTTL:          c.SessionTTL.String(),
		RuntimeTokenTTL:     c.RuntimeTokenTTL.String(),
		UDPConnectionTTL:    c.UDPConnectionTTL.String(),
		EmbeddedFRPEnabled:  boolPtr(c.EmbeddedFRPEnabled),
		FRPBindAddr:         c.FRPBindAddr,
		FRPProxyBindAddr:    c.FRPProxyBindAddr,
		FRPServerAddr:       c.FRPServerAddr,
		FRPServerPort:       c.FRPServerPort,
		FRPTransportTLS:     c.FRPTransportTLS,
		ClientConfigComment: c.ClientConfigComment,
		InitialAdmin:        c.InitialAdmin,
		Controller:          c.Controller,
		Edge:                c.Edge,
		Node:                c.Node,
		Initialized:         c.Initialized,
	}
}

func applyFileConfig(cfg *Config, fileCfg FileConfig) {
	cfg.ConfigVersion = fileCfg.ConfigVersion
	if cfg.ConfigVersion == 0 {
		cfg.ConfigVersion = 1
	}
	cfg.Mode = fileCfg.Mode
	if cfg.Mode == "" && (fileCfg.MySQLDSN != "" || fileCfg.Initialized) {
		cfg.Mode = ModeController
	}
	cfg.MySQLDSN = fileCfg.MySQLDSN
	cfg.CookieSecret = fileCfg.CookieSecret
	cfg.SessionTTL = parseDuration(fileCfg.SessionTTL, cfg.SessionTTL)
	cfg.RuntimeTokenTTL = parseDuration(fileCfg.RuntimeTokenTTL, cfg.RuntimeTokenTTL)
	cfg.UDPConnectionTTL = parseDuration(fileCfg.UDPConnectionTTL, cfg.UDPConnectionTTL)
	if fileCfg.EmbeddedFRPEnabled != nil {
		cfg.EmbeddedFRPEnabled = *fileCfg.EmbeddedFRPEnabled
	}
	cfg.FRPBindAddr = fileCfg.FRPBindAddr
	cfg.FRPProxyBindAddr = fileCfg.FRPProxyBindAddr
	cfg.FRPServerAddr = fileCfg.FRPServerAddr
	cfg.FRPServerPort = fileCfg.FRPServerPort
	cfg.FRPTransportTLS = fileCfg.FRPTransportTLS
	cfg.ClientConfigComment = fileCfg.ClientConfigComment
	cfg.InitialAdmin = fileCfg.InitialAdmin
	cfg.Initialized = fileCfg.Initialized || fileCfg.InitialAdmin.PasswordHash != ""
	cfg.Controller = mergeControllerConfig(cfg.Controller, fileCfg.Controller)
	cfg.Edge = mergeEdgeConfig(cfg.Edge, fileCfg.Edge)
	if nodeRuntimeConfigured(fileCfg.Node) {
		cfg.Node = mergeNodeRuntimeConfig(cfg.Node, fileCfg.Node)
	} else {
		// Older configurations used these two top-level fields.
		cfg.Node.FRPAdvertiseAddr = fileCfg.FRPServerAddr
		cfg.Node.FRPBindPort = fileCfg.FRPServerPort
		if cfg.Mode == ModeEdge && fileCfg.Edge.NodeName != "" {
			cfg.Node.Tag = fileCfg.Edge.NodeName
		}
	}
	if cfg.CookieSecret == "" {
		cfg.CookieSecret = "dev-change-me-before-production"
	}
	if cfg.FRPBindAddr == "" {
		cfg.FRPBindAddr = "0.0.0.0"
	}
	if cfg.FRPProxyBindAddr == "" {
		cfg.FRPProxyBindAddr = cfg.FRPBindAddr
	}
	if cfg.FRPServerAddr == "" {
		cfg.FRPServerAddr = "127.0.0.1"
	}
	if cfg.FRPServerPort == 0 {
		cfg.FRPServerPort = 7000
	}
	if cfg.Node.FRPBindPort == 0 {
		cfg.Node.FRPBindPort = cfg.FRPServerPort
	}
	if cfg.Node.FRPAdvertiseAddr == "" {
		cfg.Node.FRPAdvertiseAddr = cfg.FRPServerAddr
	}
	if cfg.Node.PortRangeStart == 0 {
		cfg.Node.PortRangeStart = 1024
	}
	if cfg.Node.PortRangeEnd == 0 {
		cfg.Node.PortRangeEnd = 65535
	}
	cfg.FRPServerAddr = cfg.Node.FRPAdvertiseAddr
	cfg.FRPServerPort = cfg.Node.FRPBindPort
	if cfg.ClientConfigComment == "" {
		cfg.ClientConfigComment = "generated by frp-control-server"
	}
}

func Validate(cfg Config) error {
	if cfg.Mode != ModeController && cfg.Mode != ModeEdge {
		return fmt.Errorf("mode must be %q or %q", ModeController, ModeEdge)
	}
	if !cfg.Initialized {
		return errors.New("configuration is not initialized")
	}
	if cfg.InitialAdmin.Username == "" || cfg.InitialAdmin.PasswordHash == "" {
		return errors.New("local administrator credential is missing")
	}
	if cfg.Mode == ModeController && cfg.MySQLDSN == "" {
		return errors.New("controller mysql configuration is missing")
	}
	if cfg.Mode == ModeEdge {
		if cfg.Edge.NodeID == "" || cfg.Edge.ControllerAddr == "" {
			return errors.New("edge enrollment information is missing")
		}
		hasEmbeddedTLS := cfg.Edge.TLS.CACertificateBase64 != "" && cfg.Edge.TLS.CertificateBase64 != "" && cfg.Edge.TLS.PrivateKeyBase64 != ""
		hasFileTLS := cfg.Edge.TLS.CAFile != "" && cfg.Edge.TLS.CertFile != "" && cfg.Edge.TLS.KeyFile != ""
		if !hasEmbeddedTLS && !hasFileTLS {
			return errors.New("edge mTLS files are missing")
		}
	}
	if err := ValidateNodeRuntime(cfg.Node); err != nil {
		return err
	}
	return nil
}

func ValidateNodeRuntime(node NodeRuntimeConfig) error {
	if node.FRPBindPort <= 0 || node.FRPBindPort > 65535 {
		return errors.New("node frp_bind_port must be between 1 and 65535")
	}
	if node.PortRangeStart < 1 || node.PortRangeEnd > 65535 || node.PortRangeStart > node.PortRangeEnd {
		return errors.New("node port range is invalid")
	}
	return nil
}

func mergeNodeRuntimeConfig(base, value NodeRuntimeConfig) NodeRuntimeConfig {
	base.Tag = value.Tag
	base.PublicAPIURL = value.PublicAPIURL
	base.FRPAdvertiseAddr = value.FRPAdvertiseAddr
	if value.FRPBindPort > 0 {
		base.FRPBindPort = value.FRPBindPort
	}
	if value.PortRangeStart > 0 {
		base.PortRangeStart = value.PortRangeStart
	}
	if value.PortRangeEnd > 0 {
		base.PortRangeEnd = value.PortRangeEnd
	}
	base.Selectable = value.Selectable
	return base
}

func nodeRuntimeConfigured(value NodeRuntimeConfig) bool {
	return value.Tag != "" || value.PublicAPIURL != "" || value.FRPAdvertiseAddr != "" || value.FRPBindPort != 0 || value.PortRangeStart != 0 || value.PortRangeEnd != 0
}

func ResolvePath(configPath, value string) string {
	if value == "" || filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(filepath.Dir(configPath), value)
}

func mergeControllerConfig(base, value ControllerConfig) ControllerConfig {
	base.EdgeAccessEnabled = value.EdgeAccessEnabled
	if value.ListenAddr != "" {
		base.ListenAddr = value.ListenAddr
	}
	if value.PublicAddress != "" {
		base.PublicAddress = value.PublicAddress
	}
	if value.HeartbeatIntervalSeconds > 0 {
		base.HeartbeatIntervalSeconds = value.HeartbeatIntervalSeconds
	}
	if value.TLS.CAFile != "" {
		base.TLS.CAFile = value.TLS.CAFile
	}
	if value.TLS.CertFile != "" {
		base.TLS.CertFile = value.TLS.CertFile
	}
	if value.TLS.KeyFile != "" {
		base.TLS.KeyFile = value.TLS.KeyFile
	}
	if value.CAKeyFile != "" {
		base.CAKeyFile = value.CAKeyFile
	}
	mergeTLSMaterial(&base.TLS, value.TLS)
	return base
}

func mergeEdgeConfig(base, value EdgeConfig) EdgeConfig {
	if value.NodeID != "" {
		base.NodeID = value.NodeID
	}
	if value.NodeName != "" {
		base.NodeName = value.NodeName
	}
	if value.ControllerAddr != "" {
		base.ControllerAddr = value.ControllerAddr
	}
	if value.ControllerAPIAddr != "" {
		base.ControllerAPIAddr = value.ControllerAPIAddr
	}
	if value.ServerName != "" {
		base.ServerName = value.ServerName
	}
	if value.StatePath != "" {
		base.StatePath = value.StatePath
	}
	if value.TLS.CAFile != "" {
		base.TLS.CAFile = value.TLS.CAFile
	}
	if value.TLS.CertFile != "" {
		base.TLS.CertFile = value.TLS.CertFile
	}
	if value.TLS.KeyFile != "" {
		base.TLS.KeyFile = value.TLS.KeyFile
	}
	mergeTLSMaterial(&base.TLS, value.TLS)
	base.ControllerAdministrationEnabled = value.ControllerAdministrationEnabled
	base.Reporting = value.Reporting
	base.RemoteCommands = value.RemoteCommands
	return base
}

func mergeTLSMaterial(base *TLSFiles, value TLSFiles) {
	if value.CACertificateBase64 != "" {
		base.CACertificateBase64 = value.CACertificateBase64
	}
	if value.CAPrivateKeyBase64 != "" {
		base.CAPrivateKeyBase64 = value.CAPrivateKeyBase64
	}
	if value.CertificateBase64 != "" {
		base.CertificateBase64 = value.CertificateBase64
	}
	if value.PrivateKeyBase64 != "" {
		base.PrivateKeyBase64 = value.PrivateKeyBase64
	}
}

func EncodePEM(value []byte) string { return base64.StdEncoding.EncodeToString(value) }
func DecodePEM(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty PEM value")
	}
	return base64.StdEncoding.DecodeString(value)
}

func applyEnv(cfg *Config) {
	if value := os.Getenv("FRP_CONTROL_MYSQL_DSN"); value != "" {
		cfg.MySQLDSN = value
	}
	cfg.HTTPAddr = env("FRP_CONTROL_HTTP_ADDR", cfg.HTTPAddr)
	cfg.CookieSecret = env("FRP_CONTROL_COOKIE_SECRET", cfg.CookieSecret)
	cfg.SessionTTL = envDuration("FRP_CONTROL_SESSION_TTL", cfg.SessionTTL)
	cfg.RuntimeTokenTTL = envDuration("FRP_CONTROL_RUNTIME_TOKEN_TTL", cfg.RuntimeTokenTTL)
	cfg.UDPConnectionTTL = envDuration("FRP_CONTROL_UDP_CONNECTION_TTL", cfg.UDPConnectionTTL)
	cfg.EmbeddedFRPEnabled = envBool("FRP_CONTROL_EMBEDDED_FRPS_ENABLED", cfg.EmbeddedFRPEnabled)
	cfg.FRPBindAddr = env("FRP_CONTROL_FRP_BIND_ADDR", cfg.FRPBindAddr)
	cfg.FRPProxyBindAddr = env("FRP_CONTROL_FRP_PROXY_BIND_ADDR", cfg.FRPProxyBindAddr)
	cfg.FRPServerAddr = env("FRP_CONTROL_FRP_SERVER_ADDR", cfg.FRPServerAddr)
	cfg.FRPServerPort = envInt("FRP_CONTROL_FRP_SERVER_PORT", cfg.FRPServerPort)
	cfg.FRPTransportTLS = envBool("FRP_CONTROL_FRP_TRANSPORT_TLS", cfg.FRPTransportTLS)
	cfg.ClientConfigComment = env("FRP_CONTROL_CLIENT_CONFIG_COMMENT", cfg.ClientConfigComment)
	// Environment overrides retain their legacy names but feed the unified node
	// runtime model used by both Controller and Edge.
	cfg.Node.FRPAdvertiseAddr = cfg.FRPServerAddr
	cfg.Node.FRPBindPort = cfg.FRPServerPort
}

func defaultConfigPath() string {
	wd, err := os.Getwd()
	if err != nil {
		return "frp-control-server.cfg.json"
	}
	return filepath.Join(wd, "frp-control-server.cfg.json")
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return parseDuration(value, fallback)
}

func parseDuration(value string, fallback time.Duration) time.Duration {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func ParseDuration(value string) (time.Duration, error) {
	return time.ParseDuration(value)
}

func boolPtr(value bool) *bool {
	return &value
}
