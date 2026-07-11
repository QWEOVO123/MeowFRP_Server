package db

import (
	"context"
	"database/sql"
	"time"
)

type BlockedInboundIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedBy int64     `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) UpsertBlockedInboundIP(ctx context.Context, ip, reason string, createdBy int64) (*BlockedInboundIP, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO blocked_inbound_ips(ip, reason, created_by)
		VALUES(?, ?, ?)
		ON DUPLICATE KEY UPDATE reason=VALUES(reason), created_by=VALUES(created_by), updated_at=CURRENT_TIMESTAMP(3)
	`, ip, reason, createdBy)
	if err != nil {
		return nil, err
	}
	return s.GetBlockedInboundIP(ctx, ip)
}

func (s *Store) GetBlockedInboundIP(ctx context.Context, ip string) (*BlockedInboundIP, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT ip, reason, created_by, created_at FROM blocked_inbound_ips WHERE ip=?
	`, ip)
	return scanBlockedInboundIP(row)
}

func (s *Store) ListBlockedInboundIPs(ctx context.Context) ([]BlockedInboundIP, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ip, reason, created_by, created_at FROM blocked_inbound_ips ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	blocks := []BlockedInboundIP{}
	for rows.Next() {
		block, err := scanBlockedInboundIP(rows)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, *block)
	}
	return blocks, rows.Err()
}

func (s *Store) DeleteBlockedInboundIP(ctx context.Context, ip string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM blocked_inbound_ips WHERE ip=?`, ip)
	return err
}

func scanBlockedInboundIP(row scanner) (*BlockedInboundIP, error) {
	var block BlockedInboundIP
	err := row.Scan(&block.IP, &block.Reason, &block.CreatedBy, &block.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return &block, err
}
