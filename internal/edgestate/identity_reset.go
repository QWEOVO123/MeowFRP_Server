package edgestate

import (
	"context"
	"log"
)

// Explicit boot action, not part of Open: opening the database for inspection
// must not wipe it. Keep durable outbound events, command dedup and local bans.
func (s *Store) ResetIdentityCache(ctx context.Context) error {
	return s.resetIdentityCache(ctx, true)
}

// Reconnecting invalidates identities, not local bans, queued commands or the
// FRP runtime itself. Startup separately discards stale process runtime state.
func (s *Store) DiscardControlIdentityCache(ctx context.Context) error {
	return s.resetIdentityCache(ctx, false)
}

func (s *Store) resetIdentityCache(ctx context.Context, boot bool) error {
	s.identityResetPending.Store(true)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tables := []string{"cached_grants", "cached_policies", "cached_tokens", "cached_users", "cached_dpi_policies", "identity_cache"}
	if boot {
		tables = append(tables, "lease_allocations", "runtime_leases", "edge_client_commands")
	}
	for _, table := range tables {
		if _, err = tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}
	// Client bans are durable local control state, not cached user identities.
	// Drop stale online presence without silently unbanning a client on reboot.
	if boot {
		if _, err = tx.ExecContext(ctx, `UPDATE edge_clients SET last_seen_at=NULL,frpc_running=0,disconnect_notified=0`); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sync_state WHERE key IN ('last_revision','last_sync_at','last_error')`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM controller_blocked_ips`); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	log.Printf("edge cache discard committed: boot=%t user/token/resource/DPI cache empty; waiting for center synchronization", boot)
	return nil
}
