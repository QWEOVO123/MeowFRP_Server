package edgestate

import "context"

// Edge health concerns only its local SQLite data file; never MySQL.
func (s *Store) CheckHealth(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE sync_state SET value=value WHERE key='last_revision'`)
	return err
}
