package db

import (
	"context"
	"database/sql"
	"time"
)

type ClientCommand struct {
	ID          int64      `json:"id"`
	ClientID    int64      `json:"client_id"`
	Command     string     `json:"command"`
	Message     string     `json:"message"`
	Status      string     `json:"status"`
	CreatedBy   int64      `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
}

func (s *Store) TouchClientHeartbeat(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE clients
		SET last_seen_at=CURRENT_TIMESTAMP(3), updated_at=CURRENT_TIMESTAMP(3)
		WHERE id=?
	`, id)
	return err
}

func (s *Store) ClearClientPresence(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE clients
		SET last_seen_at=NULL, frpc_addr='', updated_at=CURRENT_TIMESTAMP(3)
		WHERE id=?
	`, id)
	return err
}

func (s *Store) ListRecentlySeenClients(ctx context.Context, timeoutSeconds int) ([]Client, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	clients := []Client{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, token_id, client_id, status, COALESCE(ban_reason,''), COALESCE(frpc_addr,''), last_seen_at
		FROM clients
		WHERE status='active'
			AND last_seen_at IS NOT NULL
			AND TIMESTAMPDIFF(SECOND, last_seen_at, CURRENT_TIMESTAMP(3)) <= ?
		ORDER BY last_seen_at DESC
	`, timeoutSeconds)
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

func (s *Store) IsClientHeartbeatFresh(ctx context.Context, clientID int64, timeoutSeconds int) (bool, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	var fresh bool
	err := s.db.QueryRowContext(ctx, `
		SELECT last_seen_at IS NOT NULL
			AND TIMESTAMPDIFF(SECOND, last_seen_at, CURRENT_TIMESTAMP(3)) <= ?
		FROM clients
		WHERE id=?
	`, timeoutSeconds, clientID).Scan(&fresh)
	if err == sql.ErrNoRows {
		return false, ErrNotFound
	}
	return fresh, err
}

func (s *Store) ListClientsWithStaleActiveLeases(ctx context.Context, cutoff time.Time) ([]Client, error) {
	clients := []Client{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT c.id, c.user_id, c.token_id, c.client_id, c.status, COALESCE(c.ban_reason,''), COALESCE(c.frpc_addr,''), c.last_seen_at
		FROM clients c
		INNER JOIN runtime_leases l ON l.token_id=c.token_id AND l.client_id=c.client_id AND l.status='active'
		WHERE c.status='active' AND (c.last_seen_at IS NULL OR c.last_seen_at<?)
		ORDER BY c.last_seen_at ASC
	`, cutoff)
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

func (s *Store) ListClientsWithStaleHeartbeat(ctx context.Context, timeoutSeconds int) ([]Client, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 60
	}
	clients := []Client{}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT c.id, c.user_id, c.token_id, c.client_id, c.status, COALESCE(c.ban_reason,''), COALESCE(c.frpc_addr,''), c.last_seen_at
		FROM clients c
		LEFT JOIN runtime_leases l ON l.token_id=c.token_id AND l.client_id=c.client_id AND l.status='active'
		LEFT JOIN client_commands cc ON cc.client_id=c.id AND cc.status='queued'
		WHERE c.status='active'
			AND (
				(c.last_seen_at IS NOT NULL AND TIMESTAMPDIFF(SECOND, c.last_seen_at, CURRENT_TIMESTAMP(3)) > ?)
				OR (c.last_seen_at IS NULL AND l.id IS NOT NULL)
				OR (c.last_seen_at IS NULL AND cc.id IS NOT NULL)
			)
		ORDER BY c.last_seen_at ASC
	`, timeoutSeconds)
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

func (s *Store) EnqueueClientCommand(ctx context.Context, clientID, createdBy int64, command, message string) (*ClientCommand, error) {
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO client_commands(client_id, command, message, status, created_by)
		VALUES(?, ?, ?, 'queued', ?)
	`, clientID, command, message, createdBy)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetClientCommand(ctx, id)
}

func (s *Store) GetClientCommand(ctx context.Context, id int64) (*ClientCommand, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, client_id, command, message, status, created_by, created_at, delivered_at
		FROM client_commands WHERE id=?
	`, id)
	return scanClientCommand(row)
}

func (s *Store) PopQueuedClientCommands(ctx context.Context, clientID int64) ([]ClientCommand, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, client_id, command, message, status, created_by, created_at, delivered_at
		FROM client_commands
		WHERE client_id=? AND status='queued'
		ORDER BY id ASC
	`, clientID)
	if err != nil {
		return nil, err
	}
	commands := []ClientCommand{}
	ids := []int64{}
	for rows.Next() {
		command, err := scanClientCommand(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		commands = append(commands, *command)
		ids = append(ids, command.ID)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
			UPDATE client_commands
			SET status='delivered', delivered_at=CURRENT_TIMESTAMP(3)
			WHERE id=? AND status='queued'
		`, id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return commands, nil
}

func (s *Store) DeleteQueuedClientCommands(ctx context.Context, clientID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM client_commands WHERE client_id=? AND status='queued'
	`, clientID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) RevokeActiveRuntimeLeasesForClient(ctx context.Context, tokenID int64, clientID, reason string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE runtime_leases
		SET status='revoked', updated_at=CURRENT_TIMESTAMP(3)
		WHERE token_id=? AND client_id=? AND status='active'
	`, tokenID, clientID)
	if err != nil {
		return 0, err
	}
	_, _ = s.db.ExecContext(ctx, `
		UPDATE frp_proxy_sessions
		SET status='closed', close_reason=NULLIF(?, ''), closed_at=CURRENT_TIMESTAMP(3), updated_at=CURRENT_TIMESTAMP(3)
		WHERE token_id=? AND client_id=? AND status='active'
	`, reason, tokenID, clientID)
	return res.RowsAffected()
}

func scanClientCommand(row scanner) (*ClientCommand, error) {
	var command ClientCommand
	var delivered sql.NullTime
	err := row.Scan(&command.ID, &command.ClientID, &command.Command, &command.Message, &command.Status, &command.CreatedBy, &command.CreatedAt, &delivered)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if delivered.Valid {
		command.DeliveredAt = &delivered.Time
	}
	return &command, err
}
