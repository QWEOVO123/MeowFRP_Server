package edgestate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/db"
)

func (s *Store) ApplyIdentitySnapshot(ctx context.Context, payload json.RawMessage) error {
	var snapshot cluster.IdentitySnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{"cached_grants", "cached_policies", "cached_tokens", "cached_users", "cached_dpi_policies"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	for _, v := range snapshot.Users {
		if _, err = tx.ExecContext(ctx, `INSERT INTO cached_users(id,username,role,status,ban_reason) VALUES(?,?,?,?,?)`, v.ID, v.Username, v.Role, v.Status, v.BanReason); err != nil {
			return err
		}
	}
	for _, v := range snapshot.Tokens {
		var expires any
		if v.ExpiresAt != nil {
			expires = v.ExpiresAt.Format(time.RFC3339Nano)
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO cached_tokens(id,user_id,name,token_hash,status,ban_reason,max_proxy_count,expires_at) VALUES(?,?,?,?,?,?,?,?)`, v.ID, v.UserID, v.Name, v.TokenHash, v.Status, v.BanReason, v.MaxProxyCount, expires); err != nil {
			return err
		}
	}
	for _, v := range snapshot.Policies {
		encoded, _ := json.Marshal(v.AllowedProtocols)
		if _, err = tx.ExecContext(ctx, `INSERT INTO cached_policies(user_id,port_start,port_end,max_ports,allowed_protocols,enabled) VALUES(?,?,?,?,?,?)`, v.UserID, v.PortStart, v.PortEnd, v.MaxPorts, string(encoded), v.Enabled); err != nil {
			return err
		}
	}
	for _, v := range snapshot.Grants {
		if _, err = tx.ExecContext(ctx, `INSERT INTO cached_grants(id,token_id,protocol,remote_port_start,remote_port_end,max_count,domain,subdomain,enabled) VALUES(?,?,?,?,?,?,?,?,?)`, v.ID, v.TokenID, v.Protocol, v.RemotePortStart, v.RemotePortEnd, v.MaxCount, v.Domain, v.Subdomain, v.Enabled); err != nil {
			return err
		}
	}
	for _, v := range snapshot.DPIPolicies {
		encoded, _ := json.Marshal(v)
		if _, err = tx.ExecContext(ctx, `INSERT INTO cached_dpi_policies(user_id,policy_json) VALUES(?,?)`, v.UserID, string(encoded)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM blocked_inbound_ips WHERE source='controller_global'`); err != nil {
		return err
	}
	for _, v := range snapshot.BlockedIPs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO blocked_inbound_ips(ip,reason,source,created_at) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,source=excluded.source,created_at=excluded.created_at`, v.IP, v.Reason, "controller_global", v.CreatedAt.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	now := time.Now().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, `INSERT INTO sync_state(key,value) VALUES('last_revision',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, snapshot.Revision); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sync_state(key,value) VALUES('last_sync_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP`, now); err != nil {
		return err
	}
	_, _ = tx.ExecContext(ctx, `UPDATE edge_clients SET disconnect_notified=0`)
	return tx.Commit()
}

func (s *Store) Credential(ctx context.Context, tokenHash, clientID string, create bool) (*db.AccessToken, *db.User, *db.Client, error) {
	var token db.AccessToken
	var expires sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id,user_id,name,token_hash,status,ban_reason,max_proxy_count,expires_at FROM cached_tokens WHERE token_hash=?`, tokenHash).Scan(&token.ID, &token.UserID, &token.Name, &token.TokenHash, &token.Status, &token.BanReason, &token.MaxProxyCount, &expires)
	if err != nil {
		return nil, nil, nil, err
	}
	if expires.Valid {
		t, e := time.Parse(time.RFC3339Nano, expires.String)
		if e == nil {
			token.ExpiresAt = &t
		}
	}
	var user db.User
	err = s.db.QueryRowContext(ctx, `SELECT id,username,role,status,ban_reason FROM cached_users WHERE id=?`, token.UserID).Scan(&user.ID, &user.Username, &user.Role, &user.Status, &user.BanReason)
	if err != nil {
		return nil, nil, nil, err
	}
	if create {
		_, err = s.db.ExecContext(ctx, `INSERT INTO edge_clients(user_id,token_id,client_id) VALUES(?,?,?) ON CONFLICT(token_id,client_id) DO NOTHING`, user.ID, token.ID, clientID)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	var client db.Client
	var seen sql.NullString
	err = s.db.QueryRowContext(ctx, `SELECT id,user_id,token_id,client_id,status,ban_reason,last_seen_at FROM edge_clients WHERE token_id=? AND client_id=?`, token.ID, clientID).Scan(&client.ID, &client.UserID, &client.TokenID, &client.ClientID, &client.Status, &client.BanReason, &seen)
	if err != nil {
		return nil, nil, nil, err
	}
	if seen.Valid {
		t, e := time.Parse(time.RFC3339Nano, seen.String)
		if e == nil {
			client.LastSeenAt = &t
		}
	}
	return &token, &user, &client, nil
}

func (s *Store) Policy(ctx context.Context, userID int64) (*db.UserResourcePolicy, error) {
	var p db.UserResourcePolicy
	var protocols string
	err := s.db.QueryRowContext(ctx, `SELECT user_id,port_start,port_end,max_ports,allowed_protocols,enabled FROM cached_policies WHERE user_id=?`, userID).Scan(&p.UserID, &p.PortStart, &p.PortEnd, &p.MaxPorts, &protocols, &p.Enabled)
	_ = json.Unmarshal([]byte(protocols), &p.AllowedProtocols)
	return &p, err
}
func (s *Store) Grants(ctx context.Context, tokenID int64) ([]db.PortGrant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,token_id,protocol,remote_port_start,remote_port_end,max_count,domain,subdomain,enabled FROM cached_grants WHERE token_id=?`, tokenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []db.PortGrant
	for rows.Next() {
		var g db.PortGrant
		if err := rows.Scan(&g.ID, &g.TokenID, &g.Protocol, &g.RemotePortStart, &g.RemotePortEnd, &g.MaxCount, &g.Domain, &g.Subdomain, &g.Enabled); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) TouchClient(ctx context.Context, id int64, frpcRunning bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE edge_clients SET last_seen_at=?,frpc_running=? WHERE id=?`, time.Now().Format(time.RFC3339Nano), frpcRunning, id)
	return err
}

func (s *Store) TouchClientSeen(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE edge_clients SET last_seen_at=?,disconnect_notified=0 WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}
func (s *Store) ClientFresh(ctx context.Context, id int64, seconds int) bool {
	var seen sql.NullString
	if s.db.QueryRowContext(ctx, `SELECT last_seen_at FROM edge_clients WHERE id=?`, id).Scan(&seen) != nil || !seen.Valid {
		return false
	}
	t, e := time.Parse(time.RFC3339Nano, seen.String)
	return e == nil && time.Since(t) <= time.Duration(seconds)*time.Second
}
func (s *Store) RuntimeClientFresh(ctx context.Context, tokenID int64, clientID string, seconds int) bool {
	var id int64
	if s.db.QueryRowContext(ctx, `SELECT id FROM edge_clients WHERE token_id=? AND client_id=? AND status='active'`, tokenID, clientID).Scan(&id) != nil {
		return false
	}
	return s.ClientFresh(ctx, id, seconds)
}
func (s *Store) RuntimeAuthorized(ctx context.Context, userID, tokenID int64) error {
	var userStatus, userReason, tokenStatus, tokenReason string
	if err := s.db.QueryRowContext(ctx, `SELECT status,ban_reason FROM cached_users WHERE id=?`, userID).Scan(&userStatus, &userReason); err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT status,ban_reason FROM cached_tokens WHERE id=?`, tokenID).Scan(&tokenStatus, &tokenReason); err != nil {
		return err
	}
	if userStatus != "active" {
		if userReason != "" {
			return errors.New(userReason)
		}
		return errors.New("user is not active")
	}
	if tokenStatus != "active" {
		if tokenReason != "" {
			return errors.New(tokenReason)
		}
		return errors.New("token is not active")
	}
	return nil
}
func (s *Store) DisconnectWarning(ctx context.Context, id int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE edge_clients SET disconnect_notified=1 WHERE id=? AND disconnect_notified=0`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) CreateLease(ctx context.Context, lease db.RuntimeLease, allocations []db.ProxyAllocationInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE runtime_leases SET status='revoked' WHERE token_id=? AND client_id=? AND status='active'`, lease.TokenID, lease.ClientID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO runtime_leases(lease_id,user_id,token_id,client_id,runtime_token_hash,status,expires_at) VALUES(?,?,?,?,?,'active',?)`, lease.LeaseID, lease.UserID, lease.TokenID, lease.ClientID, lease.RuntimeTokenHash, lease.ExpiresAt.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	for _, a := range allocations {
		_, err = tx.ExecContext(ctx, `INSERT INTO lease_allocations(lease_id,proxy_name,proxy_type,local_ip,local_port,remote_port,domain,subdomain) VALUES(?,?,?,?,?,?,?,?)`, lease.LeaseID, a.ProxyName, a.ProxyType, a.LocalIP, a.LocalPort, a.RemotePort, a.Domain, a.Subdomain)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) RuntimeLease(ctx context.Context, hash string) (*db.RuntimeLease, error) {
	var l db.RuntimeLease
	var expires string
	err := s.db.QueryRowContext(ctx, `SELECT lease_id,user_id,token_id,client_id,runtime_token_hash,status,expires_at FROM runtime_leases WHERE runtime_token_hash=?`, hash).Scan(&l.LeaseID, &l.UserID, &l.TokenID, &l.ClientID, &l.RuntimeTokenHash, &l.Status, &expires)
	if err != nil {
		return nil, err
	}
	l.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires)
	return &l, nil
}
func (s *Store) AllocationExists(ctx context.Context, leaseID, name, kind string, port int, domain, subdomain string) bool {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM lease_allocations WHERE lease_id=? AND proxy_name=? AND proxy_type=? AND remote_port=? AND domain=? AND subdomain=?`, leaseID, name, kind, port, domain, subdomain).Scan(&n)
	return n > 0
}

func (s *Store) RemotePortInUse(ctx context.Context, protocol string, remotePort int) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM lease_allocations a
		JOIN runtime_leases l ON l.lease_id=a.lease_id
		WHERE a.proxy_type=? AND a.remote_port=? AND l.status='active' AND l.expires_at>?
	`, protocol, remotePort, time.Now()).Scan(&count)
	return count > 0, err
}
func (s *Store) RevokeClient(ctx context.Context, tokenID int64, clientID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runtime_leases SET status='revoked' WHERE token_id=? AND client_id=? AND status='active'`, tokenID, clientID)
	return err
}
func (s *Store) ClearClient(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE edge_clients SET last_seen_at=NULL,frpc_running=0,disconnect_notified=0 WHERE id=?`, id)
	return err
}

func (s *Store) StaleClients(ctx context.Context, cutoff time.Time) ([]db.Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_id,token_id,client_id,status,ban_reason,last_seen_at FROM edge_clients WHERE status='active' AND EXISTS(SELECT 1 FROM runtime_leases l WHERE l.token_id=edge_clients.token_id AND l.client_id=edge_clients.client_id AND l.status='active') AND (last_seen_at IS NULL OR last_seen_at<?)`, cutoff.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []db.Client
	for rows.Next() {
		var client db.Client
		var seen sql.NullString
		if err := rows.Scan(&client.ID, &client.UserID, &client.TokenID, &client.ClientID, &client.Status, &client.BanReason, &seen); err != nil {
			return nil, err
		}
		if seen.Valid {
			if parsed, err := time.Parse(time.RFC3339Nano, seen.String); err == nil {
				client.LastSeenAt = &parsed
			}
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func ValidateCredential(token *db.AccessToken, user *db.User, client *db.Client) error {
	if user.Role != "user" || user.Status != "active" {
		if user.BanReason != "" {
			return errors.New(user.BanReason)
		}
		return errors.New("user is not active")
	}
	if token.Status != "active" {
		if token.BanReason != "" {
			return errors.New(token.BanReason)
		}
		return errors.New("token is not active")
	}
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		return errors.New("token expired")
	}
	if client.Status != "active" {
		return errors.New(strings.TrimSpace(client.BanReason))
	}
	return nil
}
