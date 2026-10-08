package edgestate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// The revocation, reauth message and durable effect marker commit together.
// A crash before FinishCommand can replay only the original lease IDs; it must
// never enqueue another reauth or revoke a lease issued after the user relogs.
func (s *Store) DisconnectClientForCommand(ctx context.Context, commandID string, tokenID int64, clientID, reason string) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var encoded string
	err = tx.QueryRowContext(ctx, `SELECT lease_ids FROM command_disconnect_effects WHERE command_id=?`, commandID).Scan(&encoded)
	if err == nil {
		var ids []string
		if err := json.Unmarshal([]byte(encoded), &ids); err != nil {
			return nil, err
		}
		return ids, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var rowID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM edge_clients WHERE token_id=? AND client_id=?`, tokenID, clientID).Scan(&rowID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT lease_id FROM runtime_leases WHERE token_id=? AND client_id=? AND status='active'`, tokenID, clientID)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE runtime_leases SET status='revoked' WHERE token_id=? AND client_id=? AND status='active'`, tokenID, clientID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO edge_client_commands(client_row_id,command,message) VALUES(?,'reauth',?)`, rowID, reason); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(ids)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO command_disconnect_effects(command_id,lease_ids) VALUES(?,?)`, commandID, string(payload)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}
