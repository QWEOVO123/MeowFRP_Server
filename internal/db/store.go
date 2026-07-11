package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrLastAdmin = errors.New("cannot delete the last active admin user")
)

type Store struct {
	db *sql.DB
}

func Open(dsn string) (*Store, error) {
	database, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(20)
	database.SetMaxIdleConns(10)
	database.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return &Store{db: database}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

type User struct {
	ID           int64     `json:"id"`
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Status       string    `json:"status"`
	BanReason    string    `json:"ban_reason,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type AccessToken struct {
	ID            int64      `json:"id"`
	UserID        int64      `json:"user_id"`
	Name          string     `json:"name"`
	TokenHash     string     `json:"-"`
	TokenPrefix   string     `json:"token_prefix"`
	PlainToken    string     `json:"plain_token,omitempty"`
	Status        string     `json:"status"`
	BanReason     string     `json:"ban_reason,omitempty"`
	MaxProxyCount int        `json:"max_proxy_count"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type AdminAPIToken struct {
	UserID      int64     `json:"user_id"`
	TokenHash   string    `json:"-"`
	TokenPrefix string    `json:"token_prefix"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type PortGrant struct {
	ID              int64  `json:"id"`
	TokenID         int64  `json:"token_id"`
	Protocol        string `json:"protocol"`
	RemotePortStart int    `json:"remote_port_start"`
	RemotePortEnd   int    `json:"remote_port_end"`
	MaxCount        int    `json:"max_count"`
	Domain          string `json:"domain,omitempty"`
	Subdomain       string `json:"subdomain,omitempty"`
	Enabled         bool   `json:"enabled"`
}

type UserResourcePolicy struct {
	UserID           int64    `json:"user_id"`
	PortStart        int      `json:"port_start"`
	PortEnd          int      `json:"port_end"`
	MaxPorts         int      `json:"max_ports"`
	AllowedProtocols []string `json:"allowed_protocols"`
	Enabled          bool     `json:"enabled"`
}

type Client struct {
	ID         int64      `json:"id"`
	UserID     int64      `json:"user_id"`
	TokenID    int64      `json:"token_id"`
	ClientID   string     `json:"client_id"`
	Status     string     `json:"status"`
	BanReason  string     `json:"ban_reason,omitempty"`
	FrpcAddr   string     `json:"frpc_addr"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

type RuntimeLease struct {
	ID               int64
	LeaseID          string
	UserID           int64
	TokenID          int64
	ClientID         string
	RuntimeTokenHash string
	Status           string
	ExpiresAt        time.Time
}

type ProxyAllocationInput struct {
	ProxyName  string `json:"name"`
	ProxyType  string `json:"type"`
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemotePort int    `json:"remote_port,omitempty"`
	Domain     string `json:"custom_domain,omitempty"`
	Subdomain  string `json:"subdomain,omitempty"`
}

type ProxyAllocation struct {
	ID         int64
	LeaseID    string
	ProxyName  string
	ProxyType  string
	LocalIP    string
	LocalPort  int
	RemotePort int
	Domain     string
	Subdomain  string
}

func (s *Store) Migrate(ctx context.Context) error {
	for _, statement := range schemaStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	for _, statement := range schemaMigrationStatements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil && !isDuplicateColumnError(err) {
			return err
		}
	}
	return nil
}

func isDuplicateColumnError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "duplicate column") || strings.Contains(message, "1060")
}

func JoinProtocols(protocols []string) string {
	normalized := normalizeProtocolList(protocols)
	return strings.Join(normalized, ",")
}

func SplitProtocols(value string) []string {
	return normalizeProtocolList(strings.Split(value, ","))
}

func normalizeProtocolList(protocols []string) []string {
	allowed := map[string]bool{
		"tcp": true, "udp": true, "http": true, "https": true, "tcpmux": true, "stcp": true, "xtcp": true,
	}
	seen := map[string]bool{}
	var normalized []string
	for _, protocol := range protocols {
		protocol = strings.ToLower(strings.TrimSpace(protocol))
		if !allowed[protocol] || seen[protocol] {
			continue
		}
		seen[protocol] = true
		normalized = append(normalized, protocol)
	}
	return normalized
}

func (s *Store) IsInitialized(ctx context.Context) (bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE setting_key='initialized'`).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return value == "true", err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO system_settings(setting_key, value)
		VALUES(?, ?)
		ON DUPLICATE KEY UPDATE value=VALUES(value), updated_at=CURRENT_TIMESTAMP(3)
	`, key, value)
	return err
}

func (s *Store) CreateInitialAdmin(ctx context.Context, username, displayName, passwordHash string) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&count); err != nil {
		return nil, err
	}
	if count > 0 {
		return nil, errors.New("admin already exists")
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO users(username, display_name, password_hash, role, status)
		VALUES(?, ?, ?, 'admin', 'active')
	`, username, displayName, passwordHash)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO system_settings(setting_key, value)
		VALUES('initialized', 'true')
		ON DUPLICATE KEY UPDATE value='true', updated_at=CURRENT_TIMESTAMP(3)
	`); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.GetUserByID(ctx, id)
}

func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, password_hash, role, status, COALESCE(ban_reason,''), created_at, updated_at
		FROM users WHERE id=?
	`, id)
	return scanUser(row)
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, password_hash, role, status, COALESCE(ban_reason,''), created_at, updated_at
		FROM users WHERE username=?
	`, username)
	return scanUser(row)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	users := []User{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, display_name, password_hash, role, status, COALESCE(ban_reason,''), created_at, updated_at
		FROM users ORDER BY id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *user)
	}
	return users, rows.Err()
}

func (s *Store) CreateUser(ctx context.Context, username, displayName, passwordHash, role string) (*User, error) {
	if role == "" {
		role = "user"
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO users(username, display_name, password_hash, role, status)
		VALUES(?, ?, ?, ?, 'active')
	`, username, displayName, passwordHash, role)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetUserByID(ctx, id)
}

func (s *Store) CreateUserWithAccessToken(ctx context.Context, username, displayName, passwordHash, role, tokenName, plainToken, tokenHash, tokenPrefix string, maxProxyCount int) (*User, *AccessToken, error) {
	if role == "" {
		role = "user"
	}
	if tokenName == "" {
		tokenName = "HTTPS API Token"
	}
	if maxProxyCount <= 0 {
		maxProxyCount = 1
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO users(username, display_name, password_hash, role, status)
		VALUES(?, ?, ?, ?, 'active')
	`, username, displayName, passwordHash, role)
	if err != nil {
		return nil, nil, err
	}
	userID, _ := res.LastInsertId()
	res, err = tx.ExecContext(ctx, `
		INSERT INTO access_tokens(user_id, name, token_hash, token_prefix, plain_token, status, max_proxy_count)
		VALUES(?, ?, ?, ?, ?, 'active', ?)
	`, userID, tokenName, tokenHash, tokenPrefix, plainToken, maxProxyCount)
	if err != nil {
		return nil, nil, err
	}
	tokenID, _ := res.LastInsertId()
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	token, err := s.GetAccessTokenByID(ctx, tokenID)
	if err != nil {
		return nil, nil, err
	}
	return user, token, nil
}

func (s *Store) SetUserStatus(ctx context.Context, id int64, status, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET status=?, ban_reason=NULLIF(?, ''), updated_at=CURRENT_TIMESTAMP(3) WHERE id=?
	`, status, reason, id)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, id).Scan(&role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if role == "admin" {
		var activeAdminCount int
		if err := tx.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM users WHERE role='admin' AND status='active' AND id<>?
		`, id).Scan(&activeAdminCount); err != nil {
			return err
		}
		if activeAdminCount == 0 {
			return ErrLastAdmin
		}
	}

	statements := []string{
		`DELETE FROM lease_proxy_allocations WHERE lease_id IN (SELECT lease_id FROM runtime_leases WHERE user_id=?)`,
		`DELETE FROM frp_proxy_sessions WHERE user_id=?`,
		`DELETE FROM dpi_events WHERE user_id=?`,
		`DELETE FROM runtime_leases WHERE user_id=?`,
		`DELETE FROM clients WHERE user_id=?`,
		`DELETE FROM token_port_grants WHERE token_id IN (SELECT id FROM access_tokens WHERE user_id=?)`,
		`DELETE FROM access_tokens WHERE user_id=?`,
		`DELETE FROM admin_api_tokens WHERE user_id=?`,
		`DELETE FROM user_resource_policies WHERE user_id=?`,
		`DELETE FROM dpi_block_rules WHERE user_id=?`,
		`DELETE FROM dpi_user_policies WHERE user_id=?`,
		`DELETE FROM users WHERE id=?`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement, id); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) UpsertUserResourcePolicy(ctx context.Context, policy UserResourcePolicy) (*UserResourcePolicy, error) {
	if policy.MaxPorts <= 0 {
		policy.MaxPorts = 1
	}
	allowedProtocols := JoinProtocols(policy.AllowedProtocols)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_resource_policies(user_id, port_start, port_end, max_ports, allowed_protocols, enabled)
		VALUES(?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			port_start=VALUES(port_start),
			port_end=VALUES(port_end),
			max_ports=VALUES(max_ports),
			allowed_protocols=VALUES(allowed_protocols),
			enabled=VALUES(enabled),
			updated_at=CURRENT_TIMESTAMP(3)
	`, policy.UserID, policy.PortStart, policy.PortEnd, policy.MaxPorts, allowedProtocols, policy.Enabled)
	if err != nil {
		return nil, err
	}
	return s.GetUserResourcePolicy(ctx, policy.UserID)
}

func (s *Store) GetUserResourcePolicy(ctx context.Context, userID int64) (*UserResourcePolicy, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT user_id, port_start, port_end, max_ports, allowed_protocols, enabled
		FROM user_resource_policies WHERE user_id=?
	`, userID)
	return scanUserResourcePolicy(row)
}

func (s *Store) ListUserResourcePolicies(ctx context.Context) ([]UserResourcePolicy, error) {
	policies := []UserResourcePolicy{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT user_id, port_start, port_end, max_ports, allowed_protocols, enabled
		FROM user_resource_policies ORDER BY user_id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		policy, err := scanUserResourcePolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, *policy)
	}
	return policies, rows.Err()
}

func (s *Store) CreateAccessToken(ctx context.Context, userID int64, name, plainToken, tokenHash, tokenPrefix string, maxProxyCount int, expiresAt *time.Time) (*AccessToken, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO access_tokens(user_id, name, token_hash, token_prefix, plain_token, status, max_proxy_count, expires_at)
		VALUES(?, ?, ?, ?, ?, 'active', ?, ?)
	`, userID, name, tokenHash, tokenPrefix, plainToken, maxProxyCount, expiresAt)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetAccessTokenByID(ctx, id)
}

func (s *Store) CreateAdminAPIToken(ctx context.Context, userID int64, tokenHash, tokenPrefix string) (*AdminAPIToken, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO admin_api_tokens(user_id, token_hash, token_prefix, status)
		VALUES(?, ?, ?, 'active')
		ON DUPLICATE KEY UPDATE
			token_hash=VALUES(token_hash),
			token_prefix=VALUES(token_prefix),
			status='active',
			updated_at=CURRENT_TIMESTAMP(3)
	`, userID, tokenHash, tokenPrefix)
	if err != nil {
		return nil, err
	}
	return s.GetAdminAPITokenByUserID(ctx, userID)
}

func (s *Store) GetAdminAPITokenByUserID(ctx context.Context, userID int64) (*AdminAPIToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT user_id, token_hash, token_prefix, status, created_at, updated_at
		FROM admin_api_tokens WHERE user_id=?
	`, userID)
	return scanAdminAPIToken(row)
}

func (s *Store) GetAccessTokenByID(ctx context.Context, id int64) (*AccessToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, token_hash, token_prefix, COALESCE(plain_token,''), status, COALESCE(ban_reason,''), max_proxy_count, expires_at, created_at, updated_at
		FROM access_tokens WHERE id=?
	`, id)
	return scanAccessToken(row)
}

func (s *Store) GetAccessTokenByHash(ctx context.Context, hash string) (*AccessToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, name, token_hash, token_prefix, COALESCE(plain_token,''), status, COALESCE(ban_reason,''), max_proxy_count, expires_at, created_at, updated_at
		FROM access_tokens WHERE token_hash=?
	`, hash)
	return scanAccessToken(row)
}

func (s *Store) ListAccessTokens(ctx context.Context) ([]AccessToken, error) {
	tokens := []AccessToken{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, name, token_hash, token_prefix, COALESCE(plain_token,''), status, COALESCE(ban_reason,''), max_proxy_count, expires_at, created_at, updated_at
		FROM access_tokens ORDER BY id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		token, err := scanAccessToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, *token)
	}
	return tokens, rows.Err()
}

func (s *Store) SetAccessTokenStatus(ctx context.Context, id int64, status, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE access_tokens SET status=?, ban_reason=NULLIF(?, ''), updated_at=CURRENT_TIMESTAMP(3) WHERE id=?
	`, status, reason, id)
	return err
}

func (s *Store) RotateAccessToken(ctx context.Context, id int64, plainToken, tokenHash, tokenPrefix string) (*AccessToken, error) {
	_, err := s.db.ExecContext(ctx, `
		UPDATE access_tokens
		SET token_hash=?, token_prefix=?, plain_token=?, status='active', ban_reason=NULL, updated_at=CURRENT_TIMESTAMP(3)
		WHERE id=?
	`, tokenHash, tokenPrefix, plainToken, id)
	if err != nil {
		return nil, err
	}
	return s.GetAccessTokenByID(ctx, id)
}

func (s *Store) CreatePortGrant(ctx context.Context, grant PortGrant) (*PortGrant, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO token_port_grants(token_id, protocol, remote_port_start, remote_port_end, max_count, domain, subdomain, enabled)
		VALUES(?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)
	`, grant.TokenID, grant.Protocol, grant.RemotePortStart, grant.RemotePortEnd, grant.MaxCount, grant.Domain, grant.Subdomain, grant.Enabled)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_id, protocol, remote_port_start, remote_port_end, max_count, COALESCE(domain,''), COALESCE(subdomain,''), enabled
		FROM token_port_grants WHERE id=?
	`, id)
	return scanPortGrant(row)
}

func (s *Store) ListPortGrants(ctx context.Context, tokenID int64) ([]PortGrant, error) {
	grants := []PortGrant{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_id, protocol, remote_port_start, remote_port_end, max_count, COALESCE(domain,''), COALESCE(subdomain,''), enabled
		FROM token_port_grants WHERE token_id=? ORDER BY id
	`, tokenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		grant, err := scanPortGrant(rows)
		if err != nil {
			return nil, err
		}
		grants = append(grants, *grant)
	}
	return grants, rows.Err()
}

func (s *Store) FindOrCreateClient(ctx context.Context, userID, tokenID int64, clientID string) (*Client, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_id, client_id, status, COALESCE(ban_reason,''), COALESCE(frpc_addr,''), last_seen_at
		FROM clients WHERE token_id=? AND client_id=?
	`, tokenID, clientID)
	client, err := scanClient(row)
	if err == nil {
		return client, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO clients(user_id, token_id, client_id, status, last_seen_at)
		VALUES(?, ?, ?, 'active', CURRENT_TIMESTAMP(3))
	`, userID, tokenID, clientID)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	row = s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_id, client_id, status, COALESCE(ban_reason,''), COALESCE(frpc_addr,''), last_seen_at
		FROM clients WHERE id=?
	`, id)
	return scanClient(row)
}

func (s *Store) UpdateClientFRPCAddress(ctx context.Context, tokenID int64, clientID, frpcAddr string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE clients
		SET frpc_addr=?, updated_at=CURRENT_TIMESTAMP(3)
		WHERE token_id=? AND client_id=?
	`, frpcAddr, tokenID, clientID)
	return err
}

func (s *Store) GetClientByID(ctx context.Context, id int64) (*Client, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_id, client_id, status, COALESCE(ban_reason,''), COALESCE(frpc_addr,''), last_seen_at
		FROM clients WHERE id=?
	`, id)
	return scanClient(row)
}

func (s *Store) GetClient(ctx context.Context, tokenID int64, clientID string) (*Client, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_id, client_id, status, COALESCE(ban_reason,''), COALESCE(frpc_addr,''), last_seen_at
		FROM clients WHERE token_id=? AND client_id=?
	`, tokenID, clientID)
	return scanClient(row)
}

func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	clients := []Client{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, token_id, client_id, status, COALESCE(ban_reason,''), COALESCE(frpc_addr,''), last_seen_at
		FROM clients ORDER BY id DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, *client)
	}
	return clients, rows.Err()
}

func (s *Store) SetClientStatus(ctx context.Context, id int64, status, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE clients SET status=?, ban_reason=NULLIF(?, ''), updated_at=CURRENT_TIMESTAMP(3) WHERE id=?
	`, status, reason, id)
	return err
}

func (s *Store) DeleteClient(ctx context.Context, id int64) (*Client, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `
		SELECT id, user_id, token_id, client_id, status, COALESCE(ban_reason,''), COALESCE(frpc_addr,''), last_seen_at
		FROM clients WHERE id=?
	`, id)
	client, err := scanClient(row)
	if err != nil {
		return nil, err
	}

	statements := []string{
		`DELETE FROM lease_proxy_allocations WHERE lease_id IN (SELECT lease_id FROM runtime_leases WHERE token_id=? AND client_id=?)`,
		`DELETE FROM frp_proxy_sessions WHERE token_id=? AND client_id=?`,
		`DELETE FROM dpi_events WHERE token_id=? AND client_id=?`,
		`DELETE FROM runtime_leases WHERE token_id=? AND client_id=?`,
		`DELETE FROM client_commands WHERE client_id=?`,
		`DELETE FROM clients WHERE id=?`,
	}
	args := [][]any{
		{client.TokenID, client.ClientID},
		{client.TokenID, client.ClientID},
		{client.TokenID, client.ClientID},
		{client.TokenID, client.ClientID},
		{client.ID},
		{client.ID},
	}
	for i, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement, args[i]...); err != nil {
			return nil, err
		}
	}
	return client, tx.Commit()
}

func (s *Store) CreateRuntimeLease(ctx context.Context, leaseID string, userID, tokenID int64, clientID, runtimeTokenHash, runtimeTokenPrefix string, expiresAt time.Time, allocations []ProxyAllocationInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
		UPDATE runtime_leases SET status='revoked', updated_at=CURRENT_TIMESTAMP(3)
		WHERE token_id=? AND client_id=? AND status='active'
	`, tokenID, clientID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO runtime_leases(lease_id, user_id, token_id, client_id, runtime_token_hash, runtime_token_prefix, status, expires_at)
		VALUES(?, ?, ?, ?, ?, ?, 'active', ?)
	`, leaseID, userID, tokenID, clientID, runtimeTokenHash, runtimeTokenPrefix, expiresAt); err != nil {
		return err
	}
	for _, allocation := range allocations {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO lease_proxy_allocations(lease_id, proxy_name, proxy_type, local_ip, local_port, remote_port, domain, subdomain)
			VALUES(?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''))
		`, leaseID, allocation.ProxyName, allocation.ProxyType, allocation.LocalIP, allocation.LocalPort, allocation.RemotePort, allocation.Domain, allocation.Subdomain); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) GetRuntimeLeaseByTokenHash(ctx context.Context, hash string) (*RuntimeLease, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, lease_id, user_id, token_id, client_id, runtime_token_hash, status, expires_at
		FROM runtime_leases WHERE runtime_token_hash=?
	`, hash)
	return scanRuntimeLease(row)
}

func (s *Store) GetRuntimeLeaseByLeaseID(ctx context.Context, leaseID string) (*RuntimeLease, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, lease_id, user_id, token_id, client_id, runtime_token_hash, status, expires_at
		FROM runtime_leases WHERE lease_id=?
	`, leaseID)
	return scanRuntimeLease(row)
}

func (s *Store) GetLeaseAllocation(ctx context.Context, leaseID, proxyName, proxyType string, remotePort int, domain, subdomain string) (*ProxyAllocation, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, lease_id, proxy_name, proxy_type, local_ip, local_port, remote_port, COALESCE(domain,''), COALESCE(subdomain,'')
		FROM lease_proxy_allocations
		WHERE lease_id=? AND proxy_name=? AND proxy_type=? AND remote_port=? AND COALESCE(domain,'')=? AND COALESCE(subdomain,'')=?
	`, leaseID, proxyName, proxyType, remotePort, domain, subdomain)
	return scanAllocation(row)
}

func (s *Store) CountActiveProxySessions(ctx context.Context, tokenID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM frp_proxy_sessions WHERE token_id=? AND status='active'
	`, tokenID).Scan(&count)
	return count, err
}

func (s *Store) StartProxySession(ctx context.Context, lease RuntimeLease, proxyName, proxyType string, remotePort int, domain, subdomain, runID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO frp_proxy_sessions(lease_id, user_id, token_id, client_id, proxy_name, proxy_type, remote_port, domain, subdomain, run_id, status)
		VALUES(?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), NULLIF(?, ''), ?, 'active')
		ON DUPLICATE KEY UPDATE status='active', run_id=VALUES(run_id), updated_at=CURRENT_TIMESTAMP(3), closed_at=NULL
	`, lease.LeaseID, lease.UserID, lease.TokenID, lease.ClientID, proxyName, proxyType, remotePort, domain, subdomain, runID)
	return err
}

func (s *Store) CloseProxySession(ctx context.Context, leaseID, proxyName, reason string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE frp_proxy_sessions
		SET status='closed', close_reason=NULLIF(?, ''), closed_at=CURRENT_TIMESTAMP(3), updated_at=CURRENT_TIMESTAMP(3)
		WHERE lease_id=? AND proxy_name=? AND status='active'
	`, reason, leaseID, proxyName)
	return err
}

func (s *Store) Audit(ctx context.Context, actorType string, actorID int64, action, targetType, targetID, message string) {
	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO audit_logs(actor_type, actor_id, action, target_type, target_id, message)
		VALUES(?, ?, ?, ?, ?, ?)
	`, actorType, actorID, action, targetType, targetID, message)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (*User, error) {
	var user User
	err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Role, &user.Status, &user.BanReason, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &user, err
}

func scanAccessToken(row scanner) (*AccessToken, error) {
	var token AccessToken
	var expires sql.NullTime
	err := row.Scan(&token.ID, &token.UserID, &token.Name, &token.TokenHash, &token.TokenPrefix, &token.PlainToken, &token.Status, &token.BanReason, &token.MaxProxyCount, &expires, &token.CreatedAt, &token.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if expires.Valid {
		token.ExpiresAt = &expires.Time
	}
	return &token, err
}

func scanAdminAPIToken(row scanner) (*AdminAPIToken, error) {
	var token AdminAPIToken
	err := row.Scan(&token.UserID, &token.TokenHash, &token.TokenPrefix, &token.Status, &token.CreatedAt, &token.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &token, err
}

func scanPortGrant(row scanner) (*PortGrant, error) {
	var grant PortGrant
	err := row.Scan(&grant.ID, &grant.TokenID, &grant.Protocol, &grant.RemotePortStart, &grant.RemotePortEnd, &grant.MaxCount, &grant.Domain, &grant.Subdomain, &grant.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &grant, err
}

func scanUserResourcePolicy(row scanner) (*UserResourcePolicy, error) {
	var policy UserResourcePolicy
	var allowedProtocols string
	err := row.Scan(&policy.UserID, &policy.PortStart, &policy.PortEnd, &policy.MaxPorts, &allowedProtocols, &policy.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	policy.AllowedProtocols = SplitProtocols(allowedProtocols)
	return &policy, err
}

func scanClient(row scanner) (*Client, error) {
	var client Client
	var lastSeen sql.NullTime
	err := row.Scan(&client.ID, &client.UserID, &client.TokenID, &client.ClientID, &client.Status, &client.BanReason, &client.FrpcAddr, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if lastSeen.Valid {
		client.LastSeenAt = &lastSeen.Time
	}
	return &client, err
}

func scanRuntimeLease(row scanner) (*RuntimeLease, error) {
	var lease RuntimeLease
	err := row.Scan(&lease.ID, &lease.LeaseID, &lease.UserID, &lease.TokenID, &lease.ClientID, &lease.RuntimeTokenHash, &lease.Status, &lease.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &lease, err
}

func scanAllocation(row scanner) (*ProxyAllocation, error) {
	var allocation ProxyAllocation
	err := row.Scan(&allocation.ID, &allocation.LeaseID, &allocation.ProxyName, &allocation.ProxyType, &allocation.LocalIP, &allocation.LocalPort, &allocation.RemotePort, &allocation.Domain, &allocation.Subdomain)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &allocation, err
}
