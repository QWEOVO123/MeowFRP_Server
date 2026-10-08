package db

import "context"

func (s *Store) ReleaseRuntimeLease(ctx context.Context, leaseID string, tokenID int64, clientID string) (bool, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE runtime_leases SET status='revoked' WHERE lease_id=? AND token_id=? AND client_id=? AND status='active'`, leaseID, tokenID, clientID)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
