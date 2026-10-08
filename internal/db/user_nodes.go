package db

import "context"

func (s *Store) ListNodeUserAccess(ctx context.Context, nodeID string) (map[int64]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id FROM user_node_access WHERE node_id=?`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := map[int64]bool{}
	for rows.Next() {
		var userID int64
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		users[userID] = true
	}
	return users, rows.Err()
}

func (s *Store) UserNodeIDs(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM user_node_access WHERE user_id=? ORDER BY node_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		nodes = append(nodes, id)
	}
	return nodes, rows.Err()
}

func (s *Store) CanAccessNode(ctx context.Context, userID int64, nodeID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_node_access WHERE user_id=? AND node_id=?`, userID, nodeID).Scan(&count)
	return count > 0, err
}

func (s *Store) SaveUserNodeAccess(ctx context.Context, userID int64, nodes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_node_access WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, node := range nodes {
		if _, err = tx.ExecContext(ctx, `INSERT IGNORE INTO user_node_access(user_id,node_id) VALUES(?,?)`, userID, node); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE runtime_leases SET status='revoked',updated_at=CURRENT_TIMESTAMP(3) WHERE user_id=? AND status='active' AND NOT EXISTS(SELECT 1 FROM user_node_access WHERE user_id=? AND node_id='controller')`, userID, userID); err != nil {
		return err
	}
	if err = markUserIdentityDirtyTx(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit()
}
