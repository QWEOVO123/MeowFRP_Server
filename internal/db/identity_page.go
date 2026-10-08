package db

import (
	"context"
	"fmt"
	"strings"

	"frp-control-server/internal/dpi"
)

// Keyset pagination bounds the working set; no OFFSET or global token scans.
type NodeIdentityPage struct {
	Users       []User
	Tokens      []AccessToken
	Policies    []UserResourcePolicy
	Grants      []PortGrant
	DPIPolicies []dpi.Policy
	Removed     []int64
	LastID      int64
	End         bool
}

func (s *Store) ReadNodeIdentityPage(ctx context.Context, nodeID string, after int64, requested []int64, limit int) (*NodeIdentityPage, error) {
	if limit < 1 || (requested != nil && (len(requested) > limit || after != 0)) {
		return nil, fmt.Errorf("invalid identity page: requested=%d limit=%d cursor=%d", len(requested), limit, after)
	}
	p := &NodeIdentityPage{LastID: after, End: true}
	query := `SELECT u.id,u.username,u.role,u.status,COALESCE(u.ban_reason,'') FROM users u JOIN user_node_access a ON a.user_id=u.id AND a.node_id=? WHERE u.id>?`
	args := []any{nodeID, after}
	if requested != nil {
		if len(requested) == 0 {
			return p, nil
		}
		query += ` AND u.id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(requested)), ",") + `)`
		for _, id := range requested {
			args = append(args, id)
		}
	}
	query += ` ORDER BY u.id LIMIT ?`
	args = append(args, limit+1)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u User
		if err = rows.Scan(&u.ID, &u.Username, &u.Role, &u.Status, &u.BanReason); err != nil {
			rows.Close()
			return nil, err
		}
		if len(p.Users) == limit {
			p.End = false
			break
		}
		p.Users = append(p.Users, u)
		p.LastID = u.ID
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	kept := map[int64]bool{}
	for _, u := range p.Users {
		kept[u.ID] = true
	}
	for _, id := range requested {
		if !kept[id] {
			p.Removed = append(p.Removed, id)
		}
	}
	if len(p.Users) == 0 {
		return p, nil
	}
	in := strings.TrimSuffix(strings.Repeat("?,", len(p.Users)), ",")
	args = nil
	for _, u := range p.Users {
		args = append(args, u.ID)
	}
	rows, err = s.db.QueryContext(ctx, `SELECT id,user_id,name,token_hash,status,COALESCE(ban_reason,''),max_proxy_count,expires_at FROM access_tokens WHERE user_id IN (`+in+`) ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t AccessToken
		if err = rows.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.Status, &t.BanReason, &t.MaxProxyCount, &t.ExpiresAt); err != nil {
			rows.Close()
			return nil, err
		}
		p.Tokens = append(p.Tokens, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT user_id,port_start,port_end,max_ports,allowed_protocols,enabled FROM user_resource_policies WHERE user_id IN (`+in+`) ORDER BY user_id`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		v, e := scanUserResourcePolicy(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		p.Policies = append(p.Policies, *v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT g.id,g.token_id,g.protocol,g.remote_port_start,g.remote_port_end,g.max_count,COALESCE(g.domain,''),COALESCE(g.subdomain,''),g.enabled FROM token_port_grants g JOIN access_tokens t ON t.id=g.token_id WHERE t.user_id IN (`+in+`) ORDER BY g.id`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		v, e := scanPortGrant(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		p.Grants = append(p.Grants, *v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = s.db.QueryContext(ctx, `SELECT user_id,enabled,mode,enabled_detectors,block_on_any_finding,allow_http,allow_tls,allow_quic,allow_encrypted_tunnel,max_inspect_bytes,temporary_block_ttl_seconds,encrypted_tunnel_mode FROM dpi_user_policies WHERE user_id IN (`+in+`) ORDER BY user_id`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		v, e := scanDPIPolicy(rows)
		if e != nil {
			rows.Close()
			return nil, e
		}
		p.DPIPolicies = append(p.DPIPolicies, v)
	}
	err = rows.Err()
	rows.Close()
	return p, err
}
