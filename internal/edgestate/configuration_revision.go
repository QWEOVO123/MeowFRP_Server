package edgestate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

func (s *Store) ConfigurationSuperseded(ctx context.Context, kind string, payload json.RawMessage) (bool, error) {
	if kind != "update_edge_runtime_settings" && kind != "update_edge_permissions" && kind != "update_edge_advanced_settings" {
		return false, nil
	}
	var metadata struct {
		Revision int64 `json:"_configuration_revision"`
	}
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return false, err
	}
	var applied int64
	err := s.db.QueryRowContext(ctx, `SELECT revision FROM configuration_revisions WHERE kind=?`, kind).Scan(&applied)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return applied > 0 && metadata.Revision < applied, nil
}

func (s *Store) ConfirmConfiguration(ctx context.Context, kind string, payload json.RawMessage) error {
	if kind != "update_edge_runtime_settings" && kind != "update_edge_permissions" && kind != "update_edge_advanced_settings" {
		return nil
	}
	var metadata struct {
		Revision int64 `json:"_configuration_revision"`
	}
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO configuration_revisions(kind,revision) VALUES(?,?) ON CONFLICT(kind) DO UPDATE SET revision=MAX(revision,excluded.revision)`, kind, metadata.Revision)
	return err
}
