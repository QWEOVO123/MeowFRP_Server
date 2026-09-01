package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type NodeCommandRecord struct {
	CommandID   string    `json:"command_id"`
	NodeID      string    `json:"node_id"`
	CommandType string    `json:"command"`
	PayloadJSON string    `json:"-"`
	Status      string    `json:"status"`
	ResultJSON  string    `json:"result,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
type EdgeClientPresence struct {
	NodeID      string    `json:"node_id"`
	UserID      int64     `json:"user_id"`
	TokenID     int64     `json:"token_id"`
	ClientID    string    `json:"client_id"`
	FRPCRunning bool      `json:"frpc_running"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type EdgeConnectionPresence struct {
	NodeID       string    `json:"node_id"`
	ConnectionID string    `json:"id"`
	Protocol     string    `json:"protocol"`
	UserID       int64     `json:"user_id"`
	TokenID      int64     `json:"token_id"`
	ClientID     string    `json:"client_id"`
	ClientAddr   string    `json:"client_addr"`
	LeaseID      string    `json:"lease_id"`
	ProxyName    string    `json:"proxy_name"`
	ProxyType    string    `json:"proxy_type"`
	RemotePort   int       `json:"remote_port"`
	InboundAddr  string    `json:"inbound_addr"`
	InboundIP    string    `json:"inbound_ip"`
	InboundPort  int       `json:"inbound_port"`
	ServerAddr   string    `json:"server_addr"`
	OpenedAt     time.Time `json:"opened_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	CanTerminate bool      `json:"can_terminate"`
}

type EdgeNodeTraffic struct {
	NodeID          string    `json:"node_id"`
	BytesInbound    uint64    `json:"bytes_inbound"`
	BytesOutbound   uint64    `json:"bytes_outbound"`
	SamplesInbound  uint64    `json:"samples_inbound"`
	SamplesOutbound uint64    `json:"samples_outbound"`
	StartedAt       time.Time `json:"started_at"`
	CapturedAt      time.Time `json:"captured_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type NodeEventRecord struct {
	ID          int64     `json:"id"`
	NodeID      string    `json:"node_id"`
	Sequence    int64     `json:"sequence"`
	EventType   string    `json:"event_type"`
	EventID     string    `json:"event_id"`
	PayloadJSON string    `json:"payload_json"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Store) CreateNodeCommand(ctx context.Context, c NodeCommandRecord) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO node_commands(command_id,node_id,command_type,payload_json,status,expires_at) VALUES(?,?,?,?,'pending',?)`, c.CommandID, c.NodeID, c.CommandType, c.PayloadJSON, c.ExpiresAt)
	return err
}
func (s *Store) ListPendingNodeCommands(ctx context.Context, nodeID string) ([]NodeCommandRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT command_id,node_id,command_type,payload_json,status,COALESCE(result_json,''),expires_at,created_at,updated_at FROM node_commands WHERE node_id=? AND status IN('pending','delivered') AND expires_at>CURRENT_TIMESTAMP(3) ORDER BY created_at LIMIT 100`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeCommandRecord
	for rows.Next() {
		var c NodeCommandRecord
		if err := rows.Scan(&c.CommandID, &c.NodeID, &c.CommandType, &c.PayloadJSON, &c.Status, &c.ResultJSON, &c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) MarkNodeCommandDelivered(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE node_commands SET status='delivered' WHERE command_id=? AND status='pending'`, id)
	return err
}
func (s *Store) CompleteNodeCommand(ctx context.Context, nodeID, id, status, result string) error {
	if status != "succeeded" && status != "failed" {
		status = "failed"
	}
	res, err := s.db.ExecContext(ctx, `UPDATE node_commands SET status=?,result_json=? WHERE node_id=? AND command_id=?`, status, result, nodeID, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) RecordNodeEvent(ctx context.Context, nodeID string, sequence int64, eventID, eventType, payload string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO node_events(node_id,sequence,event_type,event_id,payload_json) VALUES(?,?,?,?,?)`, nodeID, sequence, eventType, eventID, payload)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err == nil && eventType == "runtime_log" {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM node_events WHERE node_id=? AND event_type='runtime_log' AND id NOT IN (SELECT id FROM (SELECT id FROM node_events WHERE node_id=? AND event_type='runtime_log' ORDER BY id DESC LIMIT 5000) AS retained_runtime_logs)`, nodeID, nodeID)
	}
	return rows > 0, err
}

func (s *Store) ReplaceEdgeClientPresence(ctx context.Context, nodeID string, clients []EdgeClientPresence) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM edge_client_presence WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	for _, c := range clients {
		_, err = tx.ExecContext(ctx, `INSERT INTO edge_client_presence(node_id,user_id,token_id,client_id,frpc_running,last_seen_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id),frpc_running=VALUES(frpc_running),last_seen_at=VALUES(last_seen_at)`, nodeID, c.UserID, c.TokenID, c.ClientID, c.FRPCRunning, c.LastSeenAt)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM edge_client_presence WHERE last_seen_at<DATE_SUB(CURRENT_TIMESTAMP(3),INTERVAL 90 SECOND)`)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ListEdgeClientPresence(ctx context.Context, nodeID string) ([]EdgeClientPresence, error) {
	query := `SELECT node_id,user_id,token_id,client_id,frpc_running,last_seen_at FROM edge_client_presence WHERE last_seen_at>=DATE_SUB(CURRENT_TIMESTAMP(3),INTERVAL 90 SECOND)`
	args := []any{}
	if nodeID != "" {
		query += ` AND node_id=?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY last_seen_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EdgeClientPresence
	for rows.Next() {
		var c EdgeClientPresence
		if err := rows.Scan(&c.NodeID, &c.UserID, &c.TokenID, &c.ClientID, &c.FRPCRunning, &c.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ReplaceEdgeConnectionPresence(ctx context.Context, nodeID string, connections []EdgeConnectionPresence) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM edge_connection_presence WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	for _, c := range connections {
		_, err = tx.ExecContext(ctx, `INSERT INTO edge_connection_presence(node_id,connection_id,protocol,user_id,token_id,client_id,client_addr,lease_id,proxy_name,proxy_type,remote_port,inbound_addr,inbound_ip,inbound_port,server_addr,opened_at,last_seen_at,can_terminate) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, nodeID, c.ConnectionID, c.Protocol, c.UserID, c.TokenID, c.ClientID, c.ClientAddr, c.LeaseID, c.ProxyName, c.ProxyType, c.RemotePort, c.InboundAddr, c.InboundIP, c.InboundPort, c.ServerAddr, c.OpenedAt, c.LastSeenAt, c.CanTerminate)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListEdgeConnectionPresence(ctx context.Context, nodeID string) ([]EdgeConnectionPresence, error) {
	query := `SELECT node_id,connection_id,protocol,user_id,token_id,client_id,client_addr,lease_id,proxy_name,proxy_type,remote_port,inbound_addr,inbound_ip,inbound_port,server_addr,opened_at,last_seen_at,can_terminate FROM edge_connection_presence WHERE updated_at>=DATE_SUB(CURRENT_TIMESTAMP(3),INTERVAL 90 SECOND)`
	args := []any{}
	if nodeID != "" {
		query += ` AND node_id=?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY last_seen_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EdgeConnectionPresence{}
	for rows.Next() {
		var c EdgeConnectionPresence
		if err := rows.Scan(&c.NodeID, &c.ConnectionID, &c.Protocol, &c.UserID, &c.TokenID, &c.ClientID, &c.ClientAddr, &c.LeaseID, &c.ProxyName, &c.ProxyType, &c.RemotePort, &c.InboundAddr, &c.InboundIP, &c.InboundPort, &c.ServerAddr, &c.OpenedAt, &c.LastSeenAt, &c.CanTerminate); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) UpsertEdgeNodeTraffic(ctx context.Context, traffic EdgeNodeTraffic) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO edge_node_traffic(node_id,bytes_inbound,bytes_outbound,samples_inbound,samples_outbound,started_at,captured_at) VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE bytes_inbound=VALUES(bytes_inbound),bytes_outbound=VALUES(bytes_outbound),samples_inbound=VALUES(samples_inbound),samples_outbound=VALUES(samples_outbound),started_at=VALUES(started_at),captured_at=VALUES(captured_at)`, traffic.NodeID, traffic.BytesInbound, traffic.BytesOutbound, traffic.SamplesInbound, traffic.SamplesOutbound, traffic.StartedAt, traffic.CapturedAt)
	return err
}

func (s *Store) ListEdgeNodeTraffic(ctx context.Context, nodeID string) ([]EdgeNodeTraffic, error) {
	query := `SELECT node_id,bytes_inbound,bytes_outbound,samples_inbound,samples_outbound,started_at,captured_at,updated_at FROM edge_node_traffic`
	args := []any{}
	if nodeID != "" {
		query += ` WHERE node_id=?`
		args = append(args, nodeID)
	}
	query += ` ORDER BY updated_at DESC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EdgeNodeTraffic{}
	for rows.Next() {
		var item EdgeNodeTraffic
		if err := rows.Scan(&item.NodeID, &item.BytesInbound, &item.BytesOutbound, &item.SamplesInbound, &item.SamplesOutbound, &item.StartedAt, &item.CapturedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) ListNodeEvents(ctx context.Context, nodeID, eventType string, limit int) ([]NodeEventRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id,node_id,sequence,event_type,COALESCE(event_id,''),payload_json,created_at FROM node_events WHERE 1=1`
	args := []any{}
	if nodeID != "" {
		query += ` AND node_id=?`
		args = append(args, nodeID)
	}
	if eventType != "" {
		query += ` AND event_type=?`
		args = append(args, eventType)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NodeEventRecord{}
	for rows.Next() {
		var item NodeEventRecord
		if err := rows.Scan(&item.ID, &item.NodeID, &item.Sequence, &item.EventType, &item.EventID, &item.PayloadJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanNodeCommand(row scanner) (*NodeCommandRecord, error) {
	var c NodeCommandRecord
	err := row.Scan(&c.CommandID, &c.NodeID, &c.CommandType, &c.PayloadJSON, &c.Status, &c.ResultJSON, &c.ExpiresAt, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}
