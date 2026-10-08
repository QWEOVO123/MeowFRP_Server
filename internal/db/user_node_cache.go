package db

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type UserNodeCacheState struct {
	NodeID          string     `json:"node_id"`
	NodeName        string     `json:"node_name"`
	BootID          string     `json:"boot_id"`
	AppliedRevision int64      `json:"applied_revision"`
	DesiredRevision int64      `json:"desired_revision"`
	CachedAt        *time.Time `json:"cached_at,omitempty"`
	Pending         bool       `json:"pending"`
}

func (s *Store) UserIdentityCacheStates(ctx context.Context, userID int64) ([]UserNodeCacheState, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.node_id,e.name,COALESCE(n.boot_id,''),c.applied_revision,c.desired_revision,c.cached_at FROM user_node_cache c JOIN edge_nodes e ON e.node_id=c.node_id LEFT JOIN node_cache_sessions n ON n.node_id=c.node_id WHERE c.user_id=? ORDER BY c.node_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	states := []UserNodeCacheState{}
	for rows.Next() {
		var v UserNodeCacheState
		var cached sql.NullTime
		if err := rows.Scan(&v.NodeID, &v.NodeName, &v.BootID, &v.AppliedRevision, &v.DesiredRevision, &cached); err != nil {
			return nil, err
		}
		if cached.Valid {
			v.CachedAt = &cached.Time
		}
		v.Pending = v.DesiredRevision > v.AppliedRevision
		states = append(states, v)
	}
	return states, rows.Err()
}

// No user FK: a deleted user's cache association must survive until its
// revocation/removal has been acknowledged by every edge that cached it.
func (s *Store) NextIdentityRevision(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, `UPDATE identity_sync_sequence SET revision=LAST_INSERT_ID(revision+1) WHERE id=1`)
	if err != nil {
		return 0, err
	}
	revision, err := result.LastInsertId()
	if err == nil && revision <= 0 {
		err = errors.New("identity revision counter is unavailable")
	}
	return revision, err
}

func (s *Store) ResetNodeIdentityCache(ctx context.Context, nodeID, sessionID, bootID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO node_cache_sessions(node_id,session_id,boot_id) VALUES(?,?,?) ON DUPLICATE KEY UPDATE session_id=VALUES(session_id),boot_id=VALUES(boot_id),updated_at=CURRENT_TIMESTAMP(3)`, nodeID, sessionID, bootID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_node_cache WHERE node_id=?`, nodeID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) MarkUserIdentityDirty(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = markUserIdentityDirtyTx(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// Commit business data and the node-targeted outbox in the same transaction.
func (s *Store) execUserIdentityChange(ctx context.Context, userID int64, query string, args ...any) (sql.Result, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if err = markUserIdentityDirtyTx(ctx, tx, userID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func markUserIdentityDirtyTx(ctx context.Context, tx *sql.Tx, userID int64) error {
	result, err := tx.ExecContext(ctx, `UPDATE identity_sync_sequence SET revision=LAST_INSERT_ID(revision+1) WHERE id=1`)
	if err != nil {
		return err
	}
	revision, err := result.LastInsertId()
	if err != nil {
		return err
	}
	if revision <= 0 {
		return errors.New("identity revision counter unavailable")
	}
	// Existing caches AND newly authorized nodes. Revoked grants remain in the
	// cache index until the removal ACK, so revocation cannot miss its old owners.
	// Select then insert: avoid MySQL 5.7 INSERT/SELECT self-subquery restrictions.
	rows, err := tx.QueryContext(ctx, `SELECT targets.node_id, COALESCE(n.session_id,'') FROM
		(SELECT node_id FROM user_node_cache WHERE user_id=? UNION SELECT node_id FROM user_node_access WHERE user_id=?) targets
		JOIN edge_nodes e ON e.node_id=targets.node_id
		LEFT JOIN node_cache_sessions n ON n.node_id=targets.node_id`, userID, userID)
	if err != nil {
		return err
	}
	type target struct{ nodeID, sessionID string }
	var targets []target
	for rows.Next() {
		var v target
		if err = rows.Scan(&v.nodeID, &v.sessionID); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range targets {
		if _, err = tx.ExecContext(ctx, `INSERT INTO user_node_cache(user_id,node_id,session_id,desired_revision) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE desired_revision=GREATEST(desired_revision,VALUES(desired_revision))`, userID, v.nodeID, v.sessionID, revision); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) PendingNodeIdentityUsers(ctx context.Context, nodeID, sessionID string) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id FROM user_node_cache WHERE node_id=? AND session_id=? AND desired_revision>applied_revision ORDER BY user_id LIMIT 64`, nodeID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		users = append(users, id)
	}
	return users, rows.Err()
}

func lockCacheSession(ctx context.Context, tx *sql.Tx, nodeID, sessionID string) error {
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT session_id FROM node_cache_sessions WHERE node_id=? FOR UPDATE`, nodeID).Scan(&current); err != nil {
		return err
	}
	if current != sessionID {
		return errors.New("superseded edge cache session")
	}
	return nil
}

func (s *Store) PrepareNodeIdentityCache(ctx context.Context, nodeID, sessionID string, revision int64, userIDs []int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockCacheSession(ctx, tx, nodeID, sessionID); err != nil {
		return err
	}
	for _, id := range userIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO user_node_cache(user_id,node_id,session_id,desired_revision) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE desired_revision=GREATEST(desired_revision,VALUES(desired_revision))`, id, nodeID, sessionID, revision); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ConfirmNodeIdentityCache(ctx context.Context, nodeID, sessionID string, revision int64, users, removed []int64, full bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockCacheSession(ctx, tx, nodeID, sessionID); err != nil {
		return err
	}
	for _, id := range users {
		if _, err = tx.ExecContext(ctx, `UPDATE user_node_cache SET applied_revision=GREATEST(applied_revision,?),cached_at=CURRENT_TIMESTAMP(3) WHERE user_id=? AND node_id=? AND session_id=?`, revision, id, nodeID, sessionID); err != nil {
			return err
		}
	}
	for _, id := range removed {
		if _, err = tx.ExecContext(ctx, `UPDATE user_node_cache SET cached_at=NULL,applied_revision=GREATEST(applied_revision,?) WHERE user_id=? AND node_id=? AND session_id=?`, revision, id, nodeID, sessionID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM user_node_cache WHERE user_id=? AND node_id=? AND session_id=? AND desired_revision<=?`, id, nodeID, sessionID, revision); err != nil {
			return err
		}
	}
	// A full snapshot has no omitted cached users. Newer mutations remain dirty.
	if full {
		if _, err = tx.ExecContext(ctx, `UPDATE user_node_cache SET cached_at=NULL,applied_revision=? WHERE node_id=? AND session_id=? AND applied_revision<?`, revision, nodeID, sessionID, revision); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM user_node_cache WHERE node_id=? AND session_id=? AND desired_revision<=? AND cached_at IS NULL`, nodeID, sessionID, revision); err != nil {
			return err
		}
	}
	return tx.Commit()
}
