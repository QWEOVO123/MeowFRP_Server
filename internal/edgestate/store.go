package edgestate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db                   *sql.DB
	identityResetPending atomic.Bool
	eventMu              sync.Mutex
	dpiEventsEnabled     func() bool
}

const maxQueuedTelemetryEvents = 5000

func (s *Store) IdentityResetPending() bool { return s.identityResetPending.Load() }

type Status struct {
	LastSyncRevision int64      `json:"last_sync_revision"`
	LastSyncAt       *time.Time `json:"last_sync_at,omitempty"`
	PendingEvents    int        `json:"pending_events"`
	LastError        string     `json:"last_error,omitempty"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	database.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := database.ExecContext(ctx, `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`); err != nil {
		_ = database.Close()
		return nil, err
	}
	store := &Store{db: database}
	if err := store.migrate(ctx); err != nil {
		_ = database.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS configuration_revisions (kind TEXT PRIMARY KEY,revision INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS sync_state (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS outbound_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_id TEXT NOT NULL UNIQUE,
			event_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			acknowledged_at TEXT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS received_commands (
			command_id TEXT PRIMARY KEY,
			command_type TEXT NOT NULL,
			payload TEXT NOT NULL,
			status TEXT NOT NULL,
			result TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS outbound_event_type_id ON outbound_events(event_type,id)`,
		`CREATE TABLE IF NOT EXISTS command_disconnect_effects (command_id TEXT PRIMARY KEY,lease_ids TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS identity_cache (
			source_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			display_name TEXT NOT NULL DEFAULT '',
			credential_hash TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL,
			policy_json TEXT NOT NULL DEFAULT '{}',
			revision INTEGER NOT NULL,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS cached_users (id INTEGER PRIMARY KEY,username TEXT NOT NULL,role TEXT NOT NULL,status TEXT NOT NULL,ban_reason TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS cached_tokens (id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,name TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,status TEXT NOT NULL,ban_reason TEXT NOT NULL DEFAULT '',max_proxy_count INTEGER NOT NULL,expires_at TEXT NULL)`,
		`CREATE TABLE IF NOT EXISTS cached_policies (user_id INTEGER PRIMARY KEY,port_start INTEGER NOT NULL,port_end INTEGER NOT NULL,max_ports INTEGER NOT NULL,allowed_protocols TEXT NOT NULL,enabled INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS cached_grants (id INTEGER PRIMARY KEY,token_id INTEGER NOT NULL,protocol TEXT NOT NULL,remote_port_start INTEGER NOT NULL,remote_port_end INTEGER NOT NULL,max_count INTEGER NOT NULL,domain TEXT NOT NULL,subdomain TEXT NOT NULL,enabled INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS edge_clients (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,token_id INTEGER NOT NULL,client_id TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',ban_reason TEXT NOT NULL DEFAULT '',last_seen_at TEXT NULL,frpc_running INTEGER NOT NULL DEFAULT 0,disconnect_notified INTEGER NOT NULL DEFAULT 0,UNIQUE(token_id,client_id))`,
		`CREATE TABLE IF NOT EXISTS runtime_leases (lease_id TEXT PRIMARY KEY,user_id INTEGER NOT NULL,token_id INTEGER NOT NULL,client_id TEXT NOT NULL,runtime_token_hash TEXT NOT NULL UNIQUE,status TEXT NOT NULL,expires_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS lease_issuers (lease_id TEXT PRIMARY KEY REFERENCES runtime_leases(lease_id) ON DELETE CASCADE,access_token_hash TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS lease_allocations (lease_id TEXT NOT NULL,proxy_name TEXT NOT NULL,proxy_type TEXT NOT NULL,local_ip TEXT NOT NULL,local_port INTEGER NOT NULL,remote_port INTEGER NOT NULL,domain TEXT NOT NULL,subdomain TEXT NOT NULL,PRIMARY KEY(lease_id,proxy_name))`,
		`CREATE TABLE IF NOT EXISTS cached_dpi_policies (user_id INTEGER PRIMARY KEY,policy_json TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS blocked_inbound_ips (ip TEXT PRIMARY KEY,reason TEXT NOT NULL,source TEXT NOT NULL DEFAULT 'local',created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS controller_blocked_ips (ip TEXT PRIMARY KEY,reason TEXT NOT NULL,created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS edge_client_commands (id INTEGER PRIMARY KEY AUTOINCREMENT,client_row_id INTEGER NOT NULL,command TEXT NOT NULL,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'queued',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,delivered_at TEXT NULL,acknowledged_at TEXT NULL)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("edge state migration: %w", err)
		}
	}
	_, _ = s.db.ExecContext(ctx, `ALTER TABLE blocked_inbound_ips ADD COLUMN source TEXT NOT NULL DEFAULT 'local'`)
	_, _ = s.db.ExecContext(ctx, `ALTER TABLE edge_clients ADD COLUMN frpc_running INTEGER NOT NULL DEFAULT 0`)
	_, _ = s.db.ExecContext(ctx, `ALTER TABLE edge_client_commands ADD COLUMN delivered_at TEXT NULL`)
	_, _ = s.db.ExecContext(ctx, `ALTER TABLE edge_client_commands ADD COLUMN acknowledged_at TEXT NULL`)
	// Separate global and node-local bans: an IP may belong to both scopes.
	if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO controller_blocked_ips(ip,reason,created_at) SELECT ip,reason,created_at FROM blocked_inbound_ips WHERE source='controller_global'`); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM blocked_inbound_ips WHERE source='controller_global'`); err != nil {
		return err
	}
	for _, kind := range []string{"runtime_log", "dpi_event"} {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM outbound_events WHERE event_type=? AND id NOT IN (SELECT id FROM outbound_events WHERE event_type=? ORDER BY id DESC LIMIT ?)`, kind, kind, maxQueuedTelemetryEvents); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Status(ctx context.Context) (Status, error) {
	var status Status
	var revision string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM sync_state WHERE key='last_revision'`).Scan(&revision)
	if err != nil && err != sql.ErrNoRows {
		return status, err
	}
	if revision != "" {
		_, _ = fmt.Sscan(revision, &status.LastSyncRevision)
	}
	var lastSync string
	err = s.db.QueryRowContext(ctx, `SELECT value FROM sync_state WHERE key='last_sync_at'`).Scan(&lastSync)
	if err != nil && err != sql.ErrNoRows {
		return status, err
	}
	if parsed, err := time.Parse(time.RFC3339Nano, lastSync); err == nil {
		status.LastSyncAt = &parsed
	}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM outbound_events WHERE acknowledged_at IS NULL`).Scan(&status.PendingEvents)
	_ = s.db.QueryRowContext(ctx, `SELECT value FROM sync_state WHERE key='last_error'`).Scan(&status.LastError)
	return status, nil
}

func (s *Store) QueueEvent(ctx context.Context, eventID, eventType string, payload any) error {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if eventType == "dpi_event" && s.dpiEventsEnabled != nil && !s.dpiEventsEnabled() {
		return nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO outbound_events(event_id,event_type,payload) VALUES(?,?,?)`, eventID, eventType, string(encoded)); err != nil {
		return err
	}
	if eventType == "runtime_log" || eventType == "dpi_event" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM outbound_events WHERE event_type=? AND id NOT IN (SELECT id FROM outbound_events WHERE event_type=? ORDER BY id DESC LIMIT ?)`, eventType, eventType, maxQueuedTelemetryEvents); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetDPIEventReporting(enabled func() bool) {
	s.eventMu.Lock()
	s.dpiEventsEnabled = enabled
	s.eventMu.Unlock()
}

// Turning reporting off discards old unsent DPI events as well as stopping
// new entries. It does not disable DPI enforcement itself.
func (s *Store) PruneDisabledDPIEvents(ctx context.Context) error {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	if s.dpiEventsEnabled == nil || s.dpiEventsEnabled() {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM outbound_events WHERE event_type='dpi_event'`)
	return err
}
