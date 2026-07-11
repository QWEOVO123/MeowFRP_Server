package db

var schemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS system_settings (
		setting_key VARCHAR(128) PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS users (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		username VARCHAR(64) NOT NULL UNIQUE,
		display_name VARCHAR(128) NOT NULL DEFAULT '',
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(32) NOT NULL,
		status VARCHAR(32) NOT NULL,
		ban_reason VARCHAR(512) NULL,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		INDEX idx_users_status(status)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS access_tokens (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		user_id BIGINT NOT NULL,
		name VARCHAR(128) NOT NULL,
		token_hash CHAR(64) NOT NULL UNIQUE,
		token_prefix VARCHAR(32) NOT NULL,
		plain_token TEXT NULL,
		status VARCHAR(32) NOT NULL,
		ban_reason VARCHAR(512) NULL,
		max_proxy_count INT NOT NULL DEFAULT 1,
		expires_at DATETIME(3) NULL,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		CONSTRAINT fk_access_tokens_user FOREIGN KEY(user_id) REFERENCES users(id),
		INDEX idx_access_tokens_user(user_id),
		INDEX idx_access_tokens_status(status)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS admin_api_tokens (
		user_id BIGINT PRIMARY KEY,
		token_hash CHAR(64) NOT NULL UNIQUE,
		token_prefix VARCHAR(32) NOT NULL,
		status VARCHAR(32) NOT NULL DEFAULT 'active',
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		CONSTRAINT fk_admin_api_tokens_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
		INDEX idx_admin_api_tokens_status(status)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS token_port_grants (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		token_id BIGINT NOT NULL,
		protocol VARCHAR(16) NOT NULL,
		remote_port_start INT NOT NULL DEFAULT 0,
		remote_port_end INT NOT NULL DEFAULT 0,
		max_count INT NOT NULL DEFAULT 1,
		domain VARCHAR(255) NULL,
		subdomain VARCHAR(128) NULL,
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		CONSTRAINT fk_token_port_grants_token FOREIGN KEY(token_id) REFERENCES access_tokens(id) ON DELETE CASCADE,
		INDEX idx_token_port_grants_token(token_id),
		INDEX idx_token_port_grants_lookup(token_id, protocol, remote_port_start, remote_port_end)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS user_resource_policies (
		user_id BIGINT PRIMARY KEY,
		port_start INT NOT NULL DEFAULT 0,
		port_end INT NOT NULL DEFAULT 0,
		max_ports INT NOT NULL DEFAULT 1,
		allowed_protocols VARCHAR(128) NOT NULL DEFAULT 'tcp,udp',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		CONSTRAINT fk_user_resource_policies_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS clients (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		user_id BIGINT NOT NULL,
		token_id BIGINT NOT NULL,
		client_id VARCHAR(128) NOT NULL,
		status VARCHAR(32) NOT NULL,
		ban_reason VARCHAR(512) NULL,
		frpc_addr VARCHAR(128) NOT NULL DEFAULT '',
		last_seen_at DATETIME(3) NULL,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		UNIQUE KEY uniq_client_token_client(token_id, client_id),
		CONSTRAINT fk_clients_user FOREIGN KEY(user_id) REFERENCES users(id),
		CONSTRAINT fk_clients_token FOREIGN KEY(token_id) REFERENCES access_tokens(id),
		INDEX idx_clients_status(status)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS client_commands (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		client_id BIGINT NOT NULL,
		command VARCHAR(32) NOT NULL,
		message VARCHAR(1024) NOT NULL DEFAULT '',
		status VARCHAR(32) NOT NULL DEFAULT 'queued',
		created_by BIGINT NOT NULL DEFAULT 0,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		delivered_at DATETIME(3) NULL,
		CONSTRAINT fk_client_commands_client FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE,
		INDEX idx_client_commands_client(client_id, status, id),
		INDEX idx_client_commands_status(status, created_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS runtime_leases (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		lease_id VARCHAR(64) NOT NULL UNIQUE,
		user_id BIGINT NOT NULL,
		token_id BIGINT NOT NULL,
		client_id VARCHAR(128) NOT NULL,
		runtime_token_hash CHAR(64) NOT NULL UNIQUE,
		runtime_token_prefix VARCHAR(32) NOT NULL,
		status VARCHAR(32) NOT NULL,
		expires_at DATETIME(3) NOT NULL,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		CONSTRAINT fk_runtime_leases_user FOREIGN KEY(user_id) REFERENCES users(id),
		CONSTRAINT fk_runtime_leases_token FOREIGN KEY(token_id) REFERENCES access_tokens(id),
		INDEX idx_runtime_leases_status(status),
		INDEX idx_runtime_leases_client(token_id, client_id)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS lease_proxy_allocations (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		lease_id VARCHAR(64) NOT NULL,
		proxy_name VARCHAR(128) NOT NULL,
		proxy_type VARCHAR(16) NOT NULL,
		local_ip VARCHAR(64) NOT NULL,
		local_port INT NOT NULL,
		remote_port INT NOT NULL DEFAULT 0,
		domain VARCHAR(255) NULL,
		subdomain VARCHAR(128) NULL,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		UNIQUE KEY uniq_lease_proxy_name(lease_id, proxy_name),
		INDEX idx_lease_proxy_lookup(lease_id, proxy_type, remote_port),
		CONSTRAINT fk_lease_proxy_allocations_lease FOREIGN KEY(lease_id) REFERENCES runtime_leases(lease_id) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS frp_proxy_sessions (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		lease_id VARCHAR(64) NOT NULL,
		user_id BIGINT NOT NULL,
		token_id BIGINT NOT NULL,
		client_id VARCHAR(128) NOT NULL,
		proxy_name VARCHAR(128) NOT NULL,
		proxy_type VARCHAR(16) NOT NULL,
		remote_port INT NOT NULL DEFAULT 0,
		domain VARCHAR(255) NULL,
		subdomain VARCHAR(128) NULL,
		run_id VARCHAR(128) NOT NULL DEFAULT '',
		status VARCHAR(32) NOT NULL,
		close_reason VARCHAR(512) NULL,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		closed_at DATETIME(3) NULL,
		UNIQUE KEY uniq_active_proxy(lease_id, proxy_name),
		INDEX idx_frp_proxy_sessions_token(token_id, status),
		INDEX idx_frp_proxy_sessions_user(user_id, status)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS audit_logs (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		actor_type VARCHAR(32) NOT NULL,
		actor_id BIGINT NOT NULL DEFAULT 0,
		action VARCHAR(64) NOT NULL,
		target_type VARCHAR(64) NOT NULL,
		target_id VARCHAR(128) NOT NULL,
		message VARCHAR(1024) NOT NULL DEFAULT '',
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		INDEX idx_audit_logs_created(created_at),
		INDEX idx_audit_logs_target(target_type, target_id)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS dpi_user_policies (
		user_id BIGINT PRIMARY KEY,
		enabled BOOLEAN NOT NULL DEFAULT FALSE,
		mode VARCHAR(32) NOT NULL DEFAULT 'monitor',
		enabled_detectors VARCHAR(255) NOT NULL DEFAULT 'http,tls,quic,encrypted_tunnel',
		block_on_any_finding BOOLEAN NOT NULL DEFAULT FALSE,
		allow_http BOOLEAN NOT NULL DEFAULT TRUE,
		allow_tls BOOLEAN NOT NULL DEFAULT TRUE,
		allow_quic BOOLEAN NOT NULL DEFAULT TRUE,
		allow_encrypted_tunnel BOOLEAN NOT NULL DEFAULT TRUE,
		max_inspect_bytes INT NOT NULL DEFAULT 8192,
		temporary_block_ttl_seconds INT NOT NULL DEFAULT 120,
		encrypted_tunnel_mode VARCHAR(32) NOT NULL DEFAULT 'monitor',
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		CONSTRAINT fk_dpi_user_policies_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS dpi_block_rules (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		user_id BIGINT NULL,
		rule_type VARCHAR(32) NOT NULL,
		value VARCHAR(512) NOT NULL,
		action VARCHAR(32) NOT NULL DEFAULT 'block',
		enabled BOOLEAN NOT NULL DEFAULT TRUE,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		CONSTRAINT fk_dpi_block_rules_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
		INDEX idx_dpi_block_rules_user(user_id, enabled),
		INDEX idx_dpi_block_rules_type(rule_type, enabled)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS blocked_inbound_ips (
		ip VARCHAR(64) PRIMARY KEY,
		reason VARCHAR(512) NOT NULL DEFAULT '',
		created_by BIGINT NOT NULL DEFAULT 0,
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
		INDEX idx_blocked_inbound_ips_created(created_at)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

	`CREATE TABLE IF NOT EXISTS dpi_events (
		id BIGINT PRIMARY KEY AUTO_INCREMENT,
		user_id BIGINT NOT NULL DEFAULT 0,
		token_id BIGINT NOT NULL DEFAULT 0,
		client_id VARCHAR(128) NOT NULL DEFAULT '',
		lease_id VARCHAR(64) NOT NULL DEFAULT '',
		proxy_name VARCHAR(128) NOT NULL DEFAULT '',
		proxy_type VARCHAR(16) NOT NULL DEFAULT '',
		remote_port INT NOT NULL DEFAULT 0,
		local_addr VARCHAR(128) NOT NULL DEFAULT '',
		remote_addr VARCHAR(128) NOT NULL DEFAULT '',
		direction VARCHAR(16) NOT NULL DEFAULT '',
		detector VARCHAR(64) NOT NULL DEFAULT '',
		protocol VARCHAR(32) NOT NULL DEFAULT '',
		host VARCHAR(255) NULL,
		sni VARCHAR(255) NULL,
		target_ip VARCHAR(64) NULL,
		action VARCHAR(32) NOT NULL,
		reason VARCHAR(512) NOT NULL DEFAULT '',
		summary VARCHAR(1024) NOT NULL DEFAULT '',
		created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
		INDEX idx_dpi_events_created(created_at),
		INDEX idx_dpi_events_user(user_id, created_at),
		INDEX idx_dpi_events_token(token_id, created_at),
		INDEX idx_dpi_events_lease(lease_id)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
}

var schemaMigrationStatements = []string{
	`ALTER TABLE access_tokens ADD COLUMN plain_token TEXT NULL AFTER token_prefix`,
	`ALTER TABLE user_resource_policies ADD COLUMN allowed_protocols VARCHAR(128) NOT NULL DEFAULT 'tcp,udp' AFTER max_ports`,
	`ALTER TABLE dpi_user_policies ADD COLUMN allow_http BOOLEAN NOT NULL DEFAULT TRUE AFTER block_on_any_finding`,
	`ALTER TABLE dpi_user_policies ADD COLUMN allow_tls BOOLEAN NOT NULL DEFAULT TRUE AFTER allow_http`,
	`ALTER TABLE dpi_user_policies ADD COLUMN allow_quic BOOLEAN NOT NULL DEFAULT TRUE AFTER allow_tls`,
	`ALTER TABLE dpi_user_policies ADD COLUMN allow_encrypted_tunnel BOOLEAN NOT NULL DEFAULT TRUE AFTER allow_quic`,
	`ALTER TABLE dpi_events ADD COLUMN local_addr VARCHAR(128) NOT NULL DEFAULT '' AFTER remote_port`,
	`ALTER TABLE dpi_events ADD COLUMN remote_addr VARCHAR(128) NOT NULL DEFAULT '' AFTER local_addr`,
	`ALTER TABLE clients ADD COLUMN frpc_addr VARCHAR(128) NOT NULL DEFAULT '' AFTER ban_reason`,
}
