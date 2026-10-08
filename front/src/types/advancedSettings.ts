export type ConfigurationMode = 'automatic' | 'manual'

export interface AdvancedSettings {
  mode: string
  configuration_mode: ConfigurationMode
  connection_tuning: {
    disable_tcp_mux: boolean
    tcp_mux_keepalive_seconds: number
    tcp_keepalive_seconds: number
    max_pool_count: number
    heartbeat_timeout_seconds: number
    user_connection_timeout_seconds: number
    mtls_handshake_timeout_seconds: number
    disable_mtls_session_tickets: boolean
    enable_mtls_session_resumption: boolean
  }
  embedded_frps_enabled: boolean
  frp_transport_tls: boolean
  frp_bind_addr: string
  frp_proxy_bind_addr: string
  session_ttl: string
  runtime_token_ttl: string
  udp_connection_ttl: string
  client_config_comment: string
  config_path: string
  http_addr: string
  node: { selectable: boolean }
  controller: { edge_access_enabled: boolean; listen_addr: string; public_address: string; heartbeat_interval_seconds: number }
  edge: {
    controller_administration_enabled: boolean
    reporting: { client_presence: boolean; connections: boolean; traffic_statistics: boolean; dpi_events: boolean; runtime_logs: boolean }
    remote_commands: { disconnect_client: boolean; disconnect_connection: boolean; block_ip: boolean; change_runtime_settings: boolean }
  }
}
