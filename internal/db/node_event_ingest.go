package db

import (
	"context"
	"encoding/json"
	"fmt"

	"frp-control-server/internal/dpi"
)

// The reliable event and its DPI view commit together, before acknowledging the edge.
func (s *Store) RecordNodeEventDurably(ctx context.Context, nodeID string, sequence int64, eventID, kind, payload string) error {
	var event dpi.Event
	if kind == "dpi_event" {
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT IGNORE INTO node_events(node_id,sequence,event_type,event_id,payload_json) VALUES(?,?,?,?,?)`, nodeID, sequence, kind, eventID, payload)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM node_events WHERE node_id=? AND event_id=?`, nodeID, eventID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return fmt.Errorf("node event sequence collision: %d", sequence)
		}
	} else if kind == "dpi_event" {
		if err := insertEdgeDPIEvent(ctx, tx, nodeID, event); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if kind == "runtime_log" {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM node_events WHERE node_id=? AND event_type='runtime_log' AND id NOT IN (SELECT id FROM (SELECT id FROM node_events WHERE node_id=? AND event_type='runtime_log' ORDER BY id DESC LIMIT 5000) AS retained_runtime_logs)`, nodeID, nodeID)
	}
	return nil
}
