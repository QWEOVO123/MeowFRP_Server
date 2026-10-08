package db

import "context"

func (s *Store) CheckHealth(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	// A live TCP connection alone does not prove the application's tables work.
	var revision int64
	if err := s.db.QueryRowContext(ctx, `SELECT revision FROM identity_sync_sequence WHERE id=1`).Scan(&revision); err != nil {
		return err
	}
	// Validate table existence/read permissions without scanning any rows.
	rows, err := s.db.QueryContext(ctx, `SELECT 1 FROM users,access_tokens,clients,runtime_leases,user_resource_policies,dpi_user_policies,token_port_grants,user_node_access,user_node_cache,node_cache_sessions,edge_nodes,blocked_inbound_ips,node_commands,node_events,edge_client_presence,edge_connection_presence,edge_node_traffic WHERE 1=0`)
	if err != nil {
		return err
	}
	rows.Close()
	_, err = s.db.ExecContext(ctx, `UPDATE identity_sync_sequence SET revision=revision WHERE id=1`)
	return err
}
