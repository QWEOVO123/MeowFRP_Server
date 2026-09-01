package edgestate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
	"frp-control-server/internal/security"
)

func (s *Store) PendingEvents(ctx context.Context) ([]cluster.EventEnvelope, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id,event_type,payload,created_at FROM outbound_events WHERE acknowledged_at IS NULL ORDER BY id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cluster.EventEnvelope
	for rows.Next() {
		var e cluster.EventEnvelope
		var created, payload string
		if err := rows.Scan(&e.EventID, &e.EventType, &payload, &created); err != nil {
			return nil, err
		}
		e.Payload = json.RawMessage(payload)
		e.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", created)
		out = append(out, e)
	}
	return out, rows.Err()
}
func (s *Store) AcknowledgeEvents(ctx context.Context, ids []string) error {
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx, `UPDATE outbound_events SET acknowledged_at=CURRENT_TIMESTAMP WHERE event_id=?`, id); err != nil {
			return err
		}
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM outbound_events WHERE acknowledged_at IS NOT NULL AND id NOT IN(SELECT id FROM outbound_events ORDER BY id DESC LIMIT 1000)`)
	return nil
}

func (s *Store) HeartbeatPayload(ctx context.Context) cluster.HeartbeatPayload {
	payload := cluster.HeartbeatPayload{}
	rows, err := s.db.QueryContext(ctx, `SELECT c.user_id,c.token_id,c.client_id,c.last_seen_at,c.frpc_running FROM edge_clients c WHERE c.status='active' AND c.last_seen_at IS NOT NULL`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p cluster.ClientPresence
			var seen string
			_ = rows.Scan(&p.UserID, &p.TokenID, &p.ClientID, &seen, &p.FRPCRunning)
			if t, e := time.Parse(time.RFC3339Nano, seen); e == nil {
				p.LastSeenAt = &t
			}
			payload.Clients = append(payload.Clients, p)
		}
	}
	payload.ClientsOnline = len(payload.Clients)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbound_events WHERE acknowledged_at IS NULL`).Scan(&payload.PendingEvents)
	return payload
}

func (s *Store) GetPolicy(ctx context.Context, flow dpiengine.FlowContext) (dpi.Policy, error) {
	if flow.UserID <= 0 {
		return dpi.DefaultPolicy(), nil
	}
	var encoded string
	err := s.db.QueryRowContext(ctx, `SELECT policy_json FROM cached_dpi_policies WHERE user_id=?`, flow.UserID).Scan(&encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return dpi.DefaultPolicy(), nil
	}
	if err != nil {
		return dpi.Policy{}, err
	}
	var policy dpi.Policy
	err = json.Unmarshal([]byte(encoded), &policy)
	return policy, err
}
func (s *Store) RecordDPIEvent(ctx context.Context, event dpi.Event) {
	eventID, _, err := security.NewOpaqueToken("dpi_")
	if err == nil {
		_ = s.QueueEvent(ctx, eventID, "dpi_event", event)
	}
}

func (s *Store) BeginCommand(ctx context.Context, command cluster.NodeCommand) (bool, *cluster.CommandResult, error) {
	var status, result string
	err := s.db.QueryRowContext(ctx, `SELECT status,result FROM received_commands WHERE command_id=?`, command.CommandID).Scan(&status, &result)
	if err == nil {
		var cached cluster.CommandResult
		if status == "executing" || json.Unmarshal([]byte(result), &cached) != nil {
			cached = cluster.CommandResult{CommandID: command.CommandID, Status: "failed", Error: "previous command execution did not complete"}
		}
		return false, &cached, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, nil, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO received_commands(command_id,command_type,payload,status) VALUES(?,?,?,'executing')`, command.CommandID, command.Command, string(command.Payload))
	return err == nil, nil, err
}
func (s *Store) FinishCommand(ctx context.Context, result cluster.CommandResult) error {
	encoded, _ := json.Marshal(result)
	_, err := s.db.ExecContext(ctx, `UPDATE received_commands SET status=?,result=?,updated_at=CURRENT_TIMESTAMP WHERE command_id=?`, result.Status, string(encoded), result.CommandID)
	return err
}

func (s *Store) UpsertBlockedIP(ctx context.Context, ip, reason string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO blocked_inbound_ips(ip,reason,source,created_at) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason,source=excluded.source,created_at=excluded.created_at`, ip, reason, "controller_command", time.Now().Format(time.RFC3339Nano))
	return err
}
func (s *Store) DeleteBlockedIP(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM blocked_inbound_ips WHERE ip=?`, ip)
	return err
}
func (s *Store) ListBlockedIPs(ctx context.Context) ([]db.BlockedInboundIP, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ip,reason,created_at FROM blocked_inbound_ips`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []db.BlockedInboundIP
	for rows.Next() {
		var b db.BlockedInboundIP
		var created string
		if err := rows.Scan(&b.IP, &b.Reason, &created); err != nil {
			return nil, err
		}
		b.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) EnqueueClientCommand(ctx context.Context, tokenID int64, clientID, command, message string) error {
	var rowID int64
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM edge_clients WHERE token_id=? AND client_id=?`, tokenID, clientID).Scan(&rowID); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO edge_client_commands(client_row_id,command,message) VALUES(?,?,?)`, rowID, command, message)
	return err
}
func (s *Store) PopClientCommands(ctx context.Context, rowID int64) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,command,message FROM edge_client_commands WHERE client_row_id=? AND status IN ('queued','delivered') ORDER BY id`, rowID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	var ids []int64
	for rows.Next() {
		var id int64
		var command, message string
		if err := rows.Scan(&id, &command, &message); err != nil {
			return nil, err
		}
		ids = append(ids, id)
		out = append(out, map[string]any{"id": id, "command": command, "message": message})
	}
	for _, id := range ids {
		_, _ = s.db.ExecContext(ctx, `UPDATE edge_client_commands SET status='delivered',delivered_at=COALESCE(delivered_at,CURRENT_TIMESTAMP) WHERE id=? AND status='queued'`, id)
	}
	return out, rows.Err()
}

func (s *Store) AcknowledgeClientCommand(ctx context.Context, commandID, rowID int64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE edge_client_commands SET status='acknowledged',acknowledged_at=CURRENT_TIMESTAMP WHERE id=? AND client_row_id=? AND status IN ('queued','delivered','acknowledged')`, commandID, rowID)
	if err != nil {
		return err
	}
	matched, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if matched == 0 {
		return db.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUnacknowledgedClientCommands(ctx context.Context, rowID int64) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM edge_client_commands WHERE client_row_id=? AND status IN ('queued','delivered')`, rowID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
