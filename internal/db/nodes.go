package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type EdgeNode struct {
	NodeID            string     `json:"node_id"`
	Name              string     `json:"name"`
	CertificateSerial string     `json:"certificate_serial"`
	Status            string     `json:"status"`
	LastSeenAt        *time.Time `json:"last_seen_at,omitempty"`
	LastRemoteAddr    string     `json:"last_remote_addr"`
	PublicAPIURL      string     `json:"public_api_url"`
	Selectable        bool       `json:"selectable"`
	CapabilitiesJSON  string     `json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

func (s *Store) CreateEnrollmentToken(ctx context.Context, tokenValue, tokenPrefix string, maxUses int, expiresAt time.Time, createdBy int64) error {
	return s.CreateEnrollmentTokenWithSettings(ctx, tokenValue, tokenPrefix, maxUses, expiresAt, createdBy, "")
}

func (s *Store) CreateEnrollmentTokenWithSettings(ctx context.Context, tokenValue, tokenPrefix string, maxUses int, expiresAt time.Time, createdBy int64, settings string) error {
	if maxUses <= 0 {
		maxUses = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO node_enrollment_tokens(token_hash,plain_token,token_prefix,max_uses,expires_at,created_by,settings_json) VALUES(SHA2(?,256),?,?,?,?,?,?)`, tokenValue, tokenValue, tokenPrefix, maxUses, expiresAt, createdBy, settings)
	return err
}

func (s *Store) ConsumeEnrollmentToken(ctx context.Context, tokenValue string) error {
	_, err := s.ConsumeEnrollmentTokenSettings(ctx, tokenValue)
	return err
}

func (s *Store) ConsumeEnrollmentTokenSettings(ctx context.Context, tokenValue string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var status string
	var maxUses, useCount int
	var expiresAt time.Time
	var settings sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT status,max_uses,use_count,expires_at,settings_json FROM node_enrollment_tokens WHERE plain_token=? OR token_hash=? OR token_hash=SHA2(?,256) FOR UPDATE`, tokenValue, tokenValue, tokenValue).Scan(&status, &maxUses, &useCount, &expiresAt, &settings)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if status != "active" || useCount >= maxUses || time.Now().After(expiresAt) {
		return "", errors.New("enrollment token is expired or already used")
	}
	newStatus := "active"
	if useCount+1 >= maxUses {
		newStatus = "used"
	}
	if _, err = tx.ExecContext(ctx, `UPDATE node_enrollment_tokens SET use_count=use_count+1,status=?,used_at=CURRENT_TIMESTAMP(3) WHERE plain_token=? OR token_hash=? OR token_hash=SHA2(?,256)`, newStatus, tokenValue, tokenValue, tokenValue); err != nil {
		return "", err
	}
	return settings.String, tx.Commit()
}

func (s *Store) UpsertEdgeNode(ctx context.Context, node EdgeNode) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO edge_nodes(node_id,name,certificate_serial,status,capabilities_json) VALUES(?,?,?,'active',?) ON DUPLICATE KEY UPDATE name=VALUES(name),certificate_serial=VALUES(certificate_serial),status='active',capabilities_json=VALUES(capabilities_json),updated_at=CURRENT_TIMESTAMP(3)`, node.NodeID, node.Name, node.CertificateSerial, node.CapabilitiesJSON)
	return err
}

func (s *Store) TouchEdgeNode(ctx context.Context, nodeID, remoteAddr, capabilitiesJSON string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE edge_nodes SET last_seen_at=CURRENT_TIMESTAMP(3),last_remote_addr=?,capabilities_json=?,updated_at=CURRENT_TIMESTAMP(3) WHERE node_id=? AND status='active'`, remoteAddr, capabilitiesJSON, nodeID)
	return err
}

func (s *Store) GetEdgeNode(ctx context.Context, nodeID string) (*EdgeNode, error) {
	var node EdgeNode
	var seen sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT node_id,name,certificate_serial,status,last_seen_at,last_remote_addr,public_api_url,selectable,capabilities_json,created_at,updated_at FROM edge_nodes WHERE node_id=?`, nodeID).Scan(&node.NodeID, &node.Name, &node.CertificateSerial, &node.Status, &seen, &node.LastRemoteAddr, &node.PublicAPIURL, &node.Selectable, &node.CapabilitiesJSON, &node.CreatedAt, &node.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if seen.Valid {
		node.LastSeenAt = &seen.Time
	}
	return &node, err
}

func (s *Store) ListEdgeNodes(ctx context.Context) ([]EdgeNode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,name,certificate_serial,status,last_seen_at,last_remote_addr,public_api_url,selectable,capabilities_json,created_at,updated_at FROM edge_nodes ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []EdgeNode
	for rows.Next() {
		var node EdgeNode
		var seen sql.NullTime
		if err := rows.Scan(&node.NodeID, &node.Name, &node.CertificateSerial, &node.Status, &seen, &node.LastRemoteAddr, &node.PublicAPIURL, &node.Selectable, &node.CapabilitiesJSON, &node.CreatedAt, &node.UpdatedAt); err != nil {
			return nil, err
		}
		if seen.Valid {
			node.LastSeenAt = &seen.Time
		}
		result = append(result, node)
	}
	return result, rows.Err()
}

func (s *Store) UpdateEdgeNodeDirectory(ctx context.Context, nodeID, name, publicAPIURL string, selectable bool) error {
	result, err := s.db.ExecContext(ctx, `UPDATE edge_nodes SET name=?,public_api_url=?,selectable=?,updated_at=CURRENT_TIMESTAMP(3) WHERE node_id=?`, name, publicAPIURL, selectable, nodeID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) ListPublicEdgeNodes(ctx context.Context) ([]EdgeNode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id,name,public_api_url,last_seen_at FROM edge_nodes WHERE status='active' AND selectable=TRUE AND public_api_url<>'' ORDER BY name,node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []EdgeNode
	for rows.Next() {
		var node EdgeNode
		var seen sql.NullTime
		if err := rows.Scan(&node.NodeID, &node.Name, &node.PublicAPIURL, &seen); err != nil {
			return nil, err
		}
		if seen.Valid {
			node.LastSeenAt = &seen.Time
		}
		result = append(result, node)
	}
	return result, rows.Err()
}

// DeleteEdgeNode removes the registration and user grants atomically. Foreign
// keys remove the node's telemetry, presence and pending commands.
func (s *Store) DeleteEdgeNode(ctx context.Context, nodeID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existing string
	if err = tx.QueryRowContext(ctx, `SELECT node_id FROM edge_nodes WHERE node_id=? FOR UPDATE`, nodeID).Scan(&existing); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_node_access WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM dpi_events WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	for _, table := range []string{"user_node_cache", "node_cache_sessions"} {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE node_id=?", nodeID); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM edge_nodes WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	return tx.Commit()
}
