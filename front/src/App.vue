<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import {
  Activity,
  Ban,
  Cable,
  CheckCircle2,
  Copy,
  Info,
  KeyRound,
  LockKeyhole,
  LogOut,
  Monitor,
  Settings,
  Plus,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldCheck,
  Sparkles,
  Trash2,
  Users,
  WandSparkles,
  X,
} from '@lucide/vue'

type User = {
  id: number
  username: string
  display_name: string
  role: string
  status: string
  ban_reason?: string
  created_at?: string
}

type AccessToken = {
  id: number
  user_id: number
  name: string
  token_prefix: string
  status: string
  ban_reason?: string
  max_proxy_count: number
  plain_token?: string
  expires_at?: string
}

type UserResourcePolicy = {
  user_id: number
  port_start: number
  port_end: number
  max_ports: number
  allowed_protocols: string[]
  enabled: boolean
}

type ClientDpiStatus = {
  enabled: boolean
  mode: string
  enabled_detectors: string[]
  blocked_traffic_types: string[]
  allowed_traffic_types: string[]
  block_on_any_finding: boolean
}

type DpiPolicy = {
  user_id: number
  enabled: boolean
  mode: string
  enabled_detectors: string[]
  block_on_any_finding: boolean
  allow_http: boolean
  allow_tls: boolean
  allow_quic: boolean
  allow_encrypted_tunnel: boolean
  max_inspect_bytes: number
  temporary_block_ttl_seconds: number
  encrypted_tunnel_mode: string
}

type DpiEvent = {
  id: number
  node_id?: string
  user_id: number
  username: string
  token_id: number
  client_id: string
  lease_id: string
  proxy_name: string
  proxy_type: string
  remote_port: number
  local_addr: string
  remote_addr: string
  direction: string
  detector: string
  protocol: string
  host?: string
  sni?: string
  target_ip?: string
  action: string
  reason: string
  summary: string
  created_at: string
}

type Client = {
  id: number
  user_id: number
  token_id: number
  client_id: string
  status: string
  ban_reason?: string
  frpc_addr: string
  frpc_running: boolean
  last_seen_at?: string
}

type ActiveConnection = {
  id: string
  protocol: string
  user_id: number
  token_id: number
  client_id: string
  client_addr: string
  lease_id: string
  proxy_name: string
  proxy_type: string
  remote_port: number
  inbound_addr: string
  inbound_ip: string
  inbound_port: number
  server_addr: string
  opened_at: string
  last_seen_at: string
  can_terminate: boolean
}

type BlockedInboundIP = {
  ip: string
  reason: string
  created_at: string
}

type BootstrapResult = {
  ok: boolean
  status?: string
  reason?: string
  lease_id?: string
  expires_in?: number
  frpc_config?: string
}

type Capabilities = {
  mode: 'controller' | 'edge' | 'unconfigured'
  configured: boolean
  config_state: string
  config_error?: string
  node_id?: string
  controller_connected?: boolean
  features: Record<string, boolean>
}

type EdgeStatus = {
  node_id: string
  node_name: string
  controller_address: string
  controller_api_address?: string
  controller_connected: boolean
  certificate_expires_at?: string
  certificate_expired?: boolean
  certificate_error?: string
  last_connection_error?: string
  state?: { last_sync_revision: number; pending_events: number; last_error?: string }
}

type NodeRuntimeSettings = {
  tag: string
  public_api_url: string
  frp_advertise_addr: string
  frp_bind_port: number
  port_range_start: number
  port_range_end: number
  selectable: boolean
}

type EdgeNode = {
  node_id: string
  name: string
  status: string
  last_seen_at?: string
  last_remote_addr: string
  public_api_url: string
  selectable: boolean
  connected: boolean
  capabilities: {
    controller_administration_enabled: boolean
    admin_username?: string
    admin_display_name?: string
    reporting: { client_presence: boolean; connections: boolean; traffic_statistics: boolean; dpi_events: boolean; runtime_logs: boolean }
    remote_commands: { disconnect_client: boolean; disconnect_connection: boolean; block_ip: boolean; change_runtime_settings: boolean }
    runtime_settings: NodeRuntimeSettings
  }
}

type EdgeClientPresence = {
  node_id: string
  user_id: number
  token_id: number
  client_id: string
  frpc_running: boolean
  last_seen_at: string
}

type EdgeConnection = ActiveConnection & { node_id: string }

type EdgeTraffic = {
  node_id: string
  bytes_inbound: number
  bytes_outbound: number
  samples_inbound: number
  samples_outbound: number
  started_at: string
  captured_at: string
}

type EdgeRuntimeLog = {
  id: number
  node_id: string
  event_id: string
  payload: { message?: string; created_at?: string }
  created_at: string
}

const navItems = [
  { id: 'overview', label: '总览', icon: Activity },
  { id: 'users', label: '用户', icon: Users },
  { id: 'clients', label: '已连接客户端', icon: Monitor },
  { id: 'clientHistory', label: '历史客户端', icon: Monitor },
  { id: 'connections', label: '连接列表', icon: Cable },
  { id: 'bans', label: '封禁列表', icon: Ban },
  { id: 'bootstrap', label: '配置下发', icon: Cable },
  { id: 'settings', label: '系统', icon: Settings },
  { id: 'dpi', label: 'DPI', icon: ShieldCheck },
] as const

type NavID = (typeof navItems)[number]['id']
const protocolOptions = ['tcp', 'udp']
const dpiDetectorOptions = [
  { id: 'http', label: 'HTTP' },
  { id: 'tls', label: 'TLS' },
  { id: 'quic', label: 'QUIC' },
  { id: 'encrypted_tunnel', label: 'SS / encrypted tunnel' },
]

const loading = ref(true)
const busy = ref(false)
const backendMessage = ref('')
const initialized = ref(false)
const authed = ref(false)
const databaseReady = ref(false)
const databaseRepairRequired = ref(false)
const activeNav = ref<NavID>('overview')
const selectedUserID = ref<number | null>(null)
const showCreateUser = ref(false)
const toast = ref('')
const lastError = ref('')
const restartNotice = ref('')
const setupMode = ref<'controller' | 'edge'>('controller')
const deploymentMode = ref<'controller' | 'edge' | 'unconfigured'>('unconfigured')
const capabilities = ref<Capabilities | null>(null)
const configError = ref('')
const edgeStatusData = ref<EdgeStatus | null>(null)
const enrollmentToken = ref('')
const edgeNodes = ref<EdgeNode[]>([])
const edgeClients = ref<EdgeClientPresence[]>([])
const edgeConnections = ref<EdgeConnection[]>([])
const edgeTraffic = ref<EdgeTraffic[]>([])
const edgeRuntimeLogs = ref<EdgeRuntimeLog[]>([])
let connectedClientsTimer: ReturnType<typeof window.setInterval> | null = null
let lastToastMessage = ''

const me = ref<User | null>(null)
const users = ref<User[]>([])
const tokens = ref<AccessToken[]>([])
const clients = ref<Client[]>([])
const connectedClients = ref<Client[]>([])
const userPolicies = ref<UserResourcePolicy[]>([])
const dpiPolicies = ref<DpiPolicy[]>([])
const dpiEvents = ref<DpiEvent[]>([])
const connections = ref<ActiveConnection[]>([])
const blockedInboundIPs = ref<BlockedInboundIP[]>([])

const setupForm = reactive({
  username: 'admin',
  password: '',
  display_name: 'Administrator',
  database: {
    host: '127.0.0.1',
    port: 3306,
    username: 'root',
    password: '',
    database: 'frp_control',
  },
})
const edgeSetupForm = reactive({
  username: 'admin',
  password: '',
  display_name: 'Node Administrator',
  node_name: '',
  controller_address: '',
  enrollment_token: '',
})
const repairForm = reactive({
  username: 'admin',
  password: '',
  database: {
    host: '127.0.0.1',
    port: 3306,
    username: 'root',
    password: '',
    database: 'frp_control',
  },
})
const loginForm = reactive({ username: 'admin', password: '' })
const userForm = reactive({ username: '', display_name: '', password: '', role: 'user' })
const policyForm = reactive({
  user_id: '',
  port_start: 6001,
  port_end: 6001,
  max_ports: 1,
  allowed_protocols: ['tcp', 'udp'],
  enabled: true,
})
const dpiForm = reactive<DpiPolicy>({
  user_id: 0,
  enabled: false,
  mode: 'monitor',
  enabled_detectors: ['http', 'tls', 'quic', 'encrypted_tunnel'],
  block_on_any_finding: false,
  allow_http: true,
  allow_tls: true,
  allow_quic: true,
  allow_encrypted_tunnel: true,
  max_inspect_bytes: 8192,
  temporary_block_ttl_seconds: 120,
  encrypted_tunnel_mode: 'monitor',
})
const bootstrapForm = reactive({
  access_token: '',
  client_id: 'device-001',
  client_version: '0.1.0',
  proxies: '[\n  {\n    "name": "ssh",\n    "type": "tcp",\n    "local_ip": "127.0.0.1",\n    "local_port": 22,\n    "remote_port": 6001\n  }\n]',
})
const bootstrapResult = ref<BootstrapResult | null>(null)
const clientPolicyResult = ref<UserResourcePolicy | null>(null)
const clientDpiStatus = ref<ClientDpiStatus | null>(null)
const clientFrpEndpoint = reactive({ addr: '', port: 0, tls: false })
const settingsForm = reactive({
	mode: 'controller',
  frp_server_addr: '127.0.0.1',
  frp_server_port: 7000,
  frp_transport_tls: false,
  client_config_comment: 'generated by frp-control-server',
  session_ttl: '1h',
  udp_connection_ttl: '10s',
  config_path: '',
	node: {
	  tag: '中心节点', public_api_url: '', frp_advertise_addr: '127.0.0.1', frp_bind_port: 7000,
	  port_range_start: 1024, port_range_end: 65535, selectable: true,
	} as NodeRuntimeSettings,
	controller: {
	  edge_access_enabled: false,
	  listen_addr: '0.0.0.0:9443',
	  public_address: '',
	  heartbeat_interval_seconds: 5,
	},
	edge: {
	  controller_administration_enabled: false,
	  reporting: { client_presence: true, connections: true, traffic_statistics: true, dpi_events: false, runtime_logs: false },
	  remote_commands: { disconnect_client: true, disconnect_connection: true, block_ip: false, change_runtime_settings: false },
	},
})
const edgeBlockForm = reactive({ node_id: '', ip: '', reason: '', scope: 'node' })
const edgeReEnrollForm = reactive({ controller_address: '', node_name: '', enrollment_token: '' })
const edgeAdminForms = reactive<Record<string, { username: string; display_name: string; password: string; password_confirm: string; controller_password: string }>>({})

class ApiError extends Error {
  path: string
  status: number

  constructor(path: string, status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.path = path
    this.status = status
  }
}

const activeUsers = computed(() => (users.value ?? []).filter((user) => user.status === 'active').length)
const activeTokens = computed(() => (tokens.value ?? []).filter((token) => token.status === 'active').length)
const activeClients = computed(() => (connectedClients.value ?? []).length)
const bannedUserList = computed(() => (users.value ?? []).filter((user) => user.status === 'banned'))
const bannedTokenList = computed(() => (tokens.value ?? []).filter((token) => token.status === 'banned'))
const bannedClientList = computed(() => (clients.value ?? []).filter((client) => client.status === 'banned'))
const banTotal = computed(() => bannedUserList.value.length + bannedTokenList.value.length + bannedClientList.value.length + blockedInboundIPs.value.length)
const safeUsers = computed(() => users.value ?? [])
const safeTokens = computed(() => tokens.value ?? [])
const safeConnectedClients = computed(() => connectedClients.value ?? [])
const selectedUser = computed(() => safeUsers.value.find((user) => user.id === selectedUserID.value) ?? null)
const selectedUserTokens = computed(() => (selectedUser.value ? tokensForUser(selectedUser.value.id) : []))
const selectedUserClients = computed(() => (selectedUser.value ? clientsForUser(selectedUser.value.id) : []))
const visibleNavItems = computed(() => deploymentMode.value === 'edge'
  ? navItems.filter((item) => item.id === 'overview' || item.id === 'settings')
  : navItems)

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: 'include',
    cache: 'no-store',
    headers: options.body ? { 'Content-Type': 'application/json', ...(options.headers ?? {}) } : options.headers,
    ...options,
  })
  const text = await response.text()
  let data: any = {}
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      const title = text.match(/<title>(.*?)<\/title>/i)?.[1]?.trim()
      const htmlStatus = text.match(/<h1>(.*?)<\/h1>/i)?.[1]?.trim()
      const message = title || htmlStatus || text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim() || `HTTP ${response.status}`
      throw new ApiError(path, response.status, `${path} 返回 ${response.status || '非 JSON'}：${message}`)
    }
  }
  if (!response.ok || data.ok === false) {
    throw new ApiError(path, response.status, data.error || data.reason || `HTTP ${response.status}`)
  }
  return data as T
}

function showToast(message: string) {
  if (message === lastToastMessage) return
  lastToastMessage = message
  toast.value = message
  window.setTimeout(() => {
    if (toast.value === message) toast.value = ''
    if (lastToastMessage === message) lastToastMessage = ''
  }, 2600)
}

function showError(error: unknown, fallback: string) {
  const message = error instanceof ApiError
    ? `${fallback}：${error.message}`
    : error instanceof Error
      ? error.message
      : fallback
  lastError.value = message
  showToast(message)
}

async function initialize() {
  loading.value = true
  backendMessage.value = ''
  try {
    const state = await api<{ initialized: boolean; database_ready: boolean; database_error?: boolean; repair_required?: boolean; mode?: 'controller' | 'edge'; config_error?: string }>('/api/v1/system/bootstrap-state')
    initialized.value = state.initialized
	deploymentMode.value = state.mode || 'unconfigured'
	configError.value = state.config_error || ''
    databaseReady.value = state.database_ready
    databaseRepairRequired.value = Boolean(state.repair_required || (state.initialized && !state.database_ready))
    if (state.initialized && state.database_ready) {
	  capabilities.value = await api<Capabilities>('/api/v1/system/capabilities')
	  deploymentMode.value = capabilities.value.mode
      await loadMe()
    }
  } catch (error) {
    backendMessage.value = error instanceof Error ? error.message : '后端连接失败'
  } finally {
    loading.value = false
  }
}

async function repairDatabase() {
  busy.value = true
  restartNotice.value = ''
  try {
    await api('/api/v1/system/repair-database', {
      method: 'POST',
      body: JSON.stringify(repairForm),
    })
    databaseReady.value = true
    databaseRepairRequired.value = false
    showToast('数据库配置已更新')
    await loadMe()
  } catch (error) {
    showError(error, '数据库修复失败')
  } finally {
    busy.value = false
  }
}

async function loadMe() {
  try {
    const data = await api<{ user: User }>('/api/v1/auth/me')
    me.value = data.user
    authed.value = true
    await refreshAll()
  } catch {
    authed.value = false
    me.value = null
  }
}

async function refreshAll() {
  lastError.value = ''
	if (deploymentMode.value === 'edge') {
	  await loadSettings()
	  try {
		edgeStatusData.value = await api<EdgeStatus>('/api/v1/admin/edge/status')
		if (!edgeReEnrollForm.controller_address) edgeReEnrollForm.controller_address = edgeStatusData.value.controller_api_address || ''
		if (!edgeReEnrollForm.node_name) edgeReEnrollForm.node_name = edgeStatusData.value.node_name || ''
	  } catch (error) { showError(error, '边缘节点状态加载失败') }
	  return
	}
  try {
    const userData = await api<{ users: User[] }>('/api/v1/admin/users')
    users.value = userData.users ?? []
  } catch (error) {
    showError(error, '用户列表加载失败')
  }
  try {
    const tokenData = await api<{ tokens: AccessToken[] }>('/api/v1/admin/tokens')
    tokens.value = tokenData.tokens ?? []
  } catch (error) {
    showError(error, '凭证列表加载失败')
  }
  try {
    const clientData = await api<{ clients: Client[] }>('/api/v1/admin/clients')
    clients.value = clientData.clients ?? []
  } catch (error) {
    showError(error, '客户端列表加载失败')
  }
  await refreshConnectedClients(true)
  try {
    const policyData = await api<{ policies: UserResourcePolicy[] }>('/api/v1/admin/user-policies')
    userPolicies.value = policyData.policies ?? []
  } catch (error) {
    userPolicies.value = []
    showError(error, '资源策略加载失败')
  }
  try {
    const dpiData = await api<{ policies: DpiPolicy[] }>('/api/v1/admin/dpi-policies')
    dpiPolicies.value = dpiData.policies ?? []
  } catch (error) {
    dpiPolicies.value = []
    showError(error, 'DPI policies failed to load')
  }
  try {
    const eventData = await api<{ events: DpiEvent[] }>('/api/v1/admin/dpi-events?limit=100')
    dpiEvents.value = eventData.events ?? []
  } catch (error) {
    dpiEvents.value = []
    showError(error, 'DPI events failed to load')
  }
  await refreshConnections(true)
  await loadSettings()
  try {
    const nodeData = await api<{ nodes: EdgeNode[] }>('/api/v1/admin/nodes')
	edgeNodes.value = (nodeData.nodes ?? []).map((node) => {
	  node.capabilities ||= {} as EdgeNode['capabilities']
	  node.capabilities.reporting ||= { client_presence: false, connections: false, traffic_statistics: false, dpi_events: false, runtime_logs: false }
	  node.capabilities.remote_commands ||= { disconnect_client: false, disconnect_connection: false, block_ip: false, change_runtime_settings: false }
	  node.capabilities.runtime_settings ||= { tag: node.name, public_api_url: node.public_api_url, frp_advertise_addr: node.last_remote_addr?.split(':')[0] || '', frp_bind_port: 7000, port_range_start: 1024, port_range_end: 65535, selectable: node.selectable }
	  const form = edgeAdminForms[node.node_id] ||= { username: '', display_name: '', password: '', password_confirm: '', controller_password: '' }
	  if (!form.password && !form.password_confirm) {
		form.username = node.capabilities.admin_username || 'admin'
		form.display_name = node.capabilities.admin_display_name || ''
	  }
	  return node
	})
	if (!edgeBlockForm.node_id && edgeNodes.value.length) edgeBlockForm.node_id = edgeNodes.value[0].node_id
  } catch (error) { showError(error, '边缘节点列表加载失败') }
	await refreshEdgeClients(true)
	await refreshEdgeTelemetry(true)
}

async function refreshConnectedClients(quiet = false) {
  try {
    const data = await api<{ clients: Client[] }>('/api/v1/admin/connected-clients')
    connectedClients.value = data.clients ?? []
  } catch (error) {
    connectedClients.value = []
    if (quiet) {
      const message = error instanceof Error ? error.message : '已连接客户端加载失败'
      lastError.value = `已连接客户端加载失败：${message}`
      return
    }
    showError(error, '已连接客户端加载失败')
  }
	if (deploymentMode.value === 'controller') await refreshEdgeClients(true)
}

async function refreshEdgeClients(quiet = false) {
  try {
    const data = await api<{ clients: EdgeClientPresence[] }>('/api/v1/admin/edge-clients')
    edgeClients.value = data.clients ?? []
  } catch (error) {
    edgeClients.value = []
    if (!quiet) showError(error, '边缘客户端列表加载失败')
  }
}

async function refreshEdgeTelemetry(quiet = false) {
  try {
    const [connectionData, trafficData, logData] = await Promise.all([
      api<{ connections: EdgeConnection[] }>('/api/v1/admin/edge-connections'),
      api<{ traffic: EdgeTraffic[] }>('/api/v1/admin/edge-traffic'),
      api<{ logs: EdgeRuntimeLog[] }>('/api/v1/admin/edge-runtime-logs?limit=100'),
    ])
    edgeConnections.value = connectionData.connections ?? []
    edgeTraffic.value = trafficData.traffic ?? []
    edgeRuntimeLogs.value = logData.logs ?? []
  } catch (error) {
    edgeConnections.value = []
    edgeTraffic.value = []
    edgeRuntimeLogs.value = []
    if (!quiet) showError(error, '边缘节点上报数据加载失败')
  }
}

async function refreshConnections(quiet = false) {
  try {
    const data = await api<{ connections: ActiveConnection[]; blocked_ips: BlockedInboundIP[] }>('/api/v1/admin/connections')
    connections.value = data.connections ?? []
    blockedInboundIPs.value = data.blocked_ips ?? []
  } catch (error) {
    connections.value = []
    blockedInboundIPs.value = []
    if (quiet) {
      const message = error instanceof Error ? error.message : '连接列表加载失败'
      lastError.value = `连接列表加载失败：${message}`
      return
    }
    showError(error, '连接列表加载失败')
  }
}

async function setupAdmin() {
  busy.value = true
  restartNotice.value = ''
  try {
    const data = await api<{ user: User; admin_token?: string; expires_at?: string; expires_in?: number; restart_required?: boolean; config_path?: string }>(
      '/api/v1/system/setup-admin',
      {
      method: 'POST',
      body: JSON.stringify(setupForm),
      },
    )
    if (data.restart_required) {
      restartNotice.value = `配置已写入 ${data.config_path || 'cfg 文件'}，请重启后端后继续。`
      showToast('需要重启后端')
      return
    }
    initialized.value = true
    databaseReady.value = true
    databaseRepairRequired.value = false
    authed.value = true
    me.value = data.user
    showToast('管理员已创建')
    await refreshAll()
  } catch (error) {
    showError(error, '创建失败')
  } finally {
    busy.value = false
  }
}

async function setupEdge() {
  busy.value = true
  restartNotice.value = ''
  try {
	const data = await api<{ node_id: string; restart_required?: boolean; config_path?: string }>('/api/v1/system/setup-edge', { method: 'POST', body: JSON.stringify(edgeSetupForm) })
	deploymentMode.value = 'edge'
	restartNotice.value = `边缘节点 ${data.node_id} 已注册，配置已写入 ${data.config_path || 'cfg 文件'}，请重启后端。`
	showToast('边缘节点注册成功')
  } catch (error) { showError(error, '边缘节点注册失败') } finally { busy.value = false }
}

async function login() {
  busy.value = true
  try {
    const data = await api<{ user: User; admin_token?: string; expires_at?: string; expires_in?: number }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify(loginForm),
    })
    me.value = data.user
    authed.value = true
    showToast('欢迎回来')
    await refreshAll()
  } catch (error) {
    showError(error, '登录失败')
  } finally {
    busy.value = false
  }
}

async function logout() {
  await api('/api/v1/auth/logout', { method: 'POST' })
  authed.value = false
  me.value = null
}

async function createUser() {
  busy.value = true
  try {
    const data = await api<{ user: User; token: AccessToken; plain_token: string }>('/api/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify(userForm),
    })
    Object.assign(userForm, { username: '', display_name: '', password: '', role: 'user' })
    await refreshAll()
    showCreateUser.value = false
    selectedUserID.value = data.user.id
    showToast('用户已创建，详情页可复制 API token')
  } catch (error) {
    showError(error, '创建失败')
  } finally {
    busy.value = false
  }
}

async function saveUserPolicy() {
  if (!policyForm.user_id) {
    showToast('请选择用户')
    return
  }
  busy.value = true
  try {
    await api(`/api/v1/admin/users/${policyForm.user_id}/policy`, {
      method: 'PUT',
      body: JSON.stringify({
        port_start: Number(policyForm.port_start),
        port_end: Number(policyForm.port_end),
        max_ports: Number(policyForm.max_ports),
        allowed_protocols: policyForm.allowed_protocols,
        enabled: Boolean(policyForm.enabled),
      }),
    })
    await refreshAll()
    showToast('资源策略已保存')
  } catch (error) {
    showError(error, '保存失败')
  } finally {
    busy.value = false
  }
}

async function saveDpiPolicy(userID = dpiForm.user_id) {
  if (!userID) {
    showToast('Select a user first')
    return
  }
  busy.value = true
  try {
    const data = await api<{ policy: DpiPolicy }>(`/api/v1/admin/users/${userID}/dpi-policy`, {
      method: 'PUT',
      body: JSON.stringify({
        enabled: Boolean(dpiForm.enabled),
        mode: dpiForm.mode,
        enabled_detectors: dpiForm.enabled_detectors,
        block_on_any_finding: Boolean(dpiForm.block_on_any_finding),
        allow_http: Boolean(dpiForm.allow_http),
        allow_tls: Boolean(dpiForm.allow_tls),
        allow_quic: Boolean(dpiForm.allow_quic),
        allow_encrypted_tunnel: Boolean(dpiForm.allow_encrypted_tunnel),
        max_inspect_bytes: Number(dpiForm.max_inspect_bytes),
        temporary_block_ttl_seconds: Number(dpiForm.temporary_block_ttl_seconds),
        encrypted_tunnel_mode: dpiForm.encrypted_tunnel_mode,
      }),
    })
    const index = dpiPolicies.value.findIndex((policy) => policy.user_id === userID)
    if (index >= 0) dpiPolicies.value[index] = data.policy
    else dpiPolicies.value.push(data.policy)
    showToast('DPI policy saved')
  } catch (error) {
    showError(error, 'DPI policy save failed')
  } finally {
    busy.value = false
  }
}

async function saveDpiGateway(userID: number, enabled: boolean) {
  loadDpiForm(userID)
  dpiForm.enabled = enabled
  await saveDpiPolicy(userID)
}

function openDpiConfig(user: User) {
  loadDpiForm(user.id)
  activeNav.value = 'dpi'
}

async function setStatus(kind: 'users' | 'tokens' | 'clients', id: number, action: 'ban' | 'unban') {
  const reason = action === 'ban' ? window.prompt('封禁原因', 'policy violation') : ''
  if (action === 'ban' && reason === null) return
  busy.value = true
  try {
    await api(`/api/v1/admin/${kind}/${id}/${action}`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    })
    await refreshAll()
    showToast(action === 'ban' ? '已封禁' : '已解封')
  } catch (error) {
    showError(error, action === 'ban' ? '封禁失败' : '解封失败')
  } finally {
    busy.value = false
  }
}

async function sendClientCommand(client: Client, command: 'stop_frpc' | 'show_warning' | 'reauth') {
  const labels: Record<typeof command, string> = {
    stop_frpc: '远程关闭 frpc',
    show_warning: '弹窗提醒',
    reauth: '要求重新鉴权',
  }
  let message = ''
  if (command === 'show_warning') {
    const input = window.prompt('弹窗内容', '服务端检测到违规行为，请规范操作')
    if (input === null) return
    message = input
  } else {
    const confirmed = window.confirm(`确认对 ${client.client_id} 下发「${labels[command]}」命令？`)
    if (!confirmed) return
  }
  busy.value = true
  try {
    await api(`/api/v1/admin/clients/${client.id}/commands`, {
      method: 'POST',
      body: JSON.stringify({ command, message }),
    })
    await refreshConnectedClients()
    await refreshConnections()
    showToast('命令已进入队列')
  } catch (error) {
    showError(error, '命令下发失败')
  } finally {
    busy.value = false
  }
}

async function deleteUser(user: User) {
  if (me.value?.id === user.id) {
    showToast('不能删除当前登录的管理员')
    return
  }
  const confirmed = window.confirm(
    `确认删除用户 ${user.username}？\n\n此操作会删除该用户的 API token、客户端记录、租约、连接会话、资源策略和 DPI 配置，并断开当前连接。`,
  )
  if (!confirmed) return
  busy.value = true
  try {
    await api(`/api/v1/admin/users/${user.id}`, { method: 'DELETE' })
    if (selectedUserID.value === user.id) selectedUserID.value = null
    await refreshAll()
    showToast('用户已删除')
  } catch (error) {
    showError(error, '删除用户失败')
  } finally {
    busy.value = false
  }
}

async function deleteClient(client: Client) {
  const confirmed = window.confirm(
    `确认删除客户端记录？\n\nClient ID: ${client.client_id}\n用户: ${userName(client.user_id)}\n\n此操作会删除该客户端的命令队列、运行租约、代理会话和 DPI 事件，并断开当前连接。`,
  )
  if (!confirmed) return
  busy.value = true
  try {
    await api(`/api/v1/admin/clients/${client.id}`, { method: 'DELETE' })
    await refreshAll()
    showToast('客户端记录已删除')
  } catch (error) {
    showError(error, '删除客户端失败')
  } finally {
    busy.value = false
  }
}

async function disconnectConnection(connection: ActiveConnection) {
  if (connection.protocol !== 'tcp') {
    showToast('UDP 连接不能发送 RST')
    return
  }
  const confirmed = window.confirm(`确认断开 ${connection.inbound_addr} -> ${connection.proxy_name} ?`)
  if (!confirmed) return
  busy.value = true
  try {
    await api(`/api/v1/admin/connections/${connection.id}/disconnect`, { method: 'POST' })
    await refreshConnections()
    showToast('TCP 连接已断开')
  } catch (error) {
    showError(error, '断开连接失败')
  } finally {
    busy.value = false
  }
}

async function blockConnectionIP(connection: ActiveConnection) {
  const reason = window.prompt('拉黑原因', `blocked from connection ${connection.id}`)
  if (reason === null) return
  busy.value = true
  try {
    await api('/api/v1/admin/blocked-ips', {
      method: 'POST',
      body: JSON.stringify({ ip: connection.inbound_ip, reason }),
    })
    await refreshConnections()
    showToast('入站 IP 已拉黑')
  } catch (error) {
    showError(error, '拉黑失败')
  } finally {
    busy.value = false
  }
}

async function unblockInboundIP(ip: string) {
  busy.value = true
  try {
    await api(`/api/v1/admin/blocked-ips/${encodeURIComponent(ip)}`, { method: 'DELETE' })
    await refreshConnections()
    showToast('入站 IP 已解除拉黑')
  } catch (error) {
    showError(error, '解除拉黑失败')
  } finally {
    busy.value = false
  }
}

async function rotateToken(token: AccessToken) {
  const confirmed = window.confirm('重新生成后，旧 token 会立即失效。确定继续吗？')
  if (!confirmed) return
  busy.value = true
  try {
    await api<{ token: AccessToken; plain_token: string }>(`/api/v1/admin/tokens/${token.id}/rotate`, {
      method: 'POST',
    })
    await refreshAll()
    showToast('Token 已重新生成')
  } catch (error) {
    showError(error, '重新生成失败')
  } finally {
    busy.value = false
  }
}

async function runBootstrap() {
  busy.value = true
  bootstrapResult.value = null
  try {
    const payload = {
      access_token: bootstrapForm.access_token,
      client_id: bootstrapForm.client_id,
      client_version: bootstrapForm.client_version,
      proxies: JSON.parse(bootstrapForm.proxies),
    }
    const response = await fetch('/api/v1/client/bootstrap', {
      credentials: 'include',
      cache: 'no-store',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = await response.json()
    if (!response.ok) {
      throw new Error(data.error || `HTTP ${response.status}`)
    }
    bootstrapResult.value = data
  } catch (error) {
    bootstrapResult.value = {
      ok: false,
      status: 'error',
      reason: error instanceof Error ? error.message : '请求失败',
    }
  } finally {
    busy.value = false
  }
}

async function loadSettings() {
  try {
    const data = await api<{ settings: typeof settingsForm }>('/api/v1/admin/system-settings')
	const incoming = data.settings as any
	Object.assign(settingsForm, incoming)
	if (incoming.controller) Object.assign(settingsForm.controller, incoming.controller)
	if (incoming.node) Object.assign(settingsForm.node, incoming.node)
	if (incoming.edge?.reporting) Object.assign(settingsForm.edge.reporting, incoming.edge.reporting)
	if (incoming.edge?.remote_commands) Object.assign(settingsForm.edge.remote_commands, incoming.edge.remote_commands)
  } catch {
    // Setup mode or older backend; keep defaults visible.
  }
}

async function saveSettings() {
  busy.value = true
  try {
	const payload = deploymentMode.value === 'edge'
	  ? { node: settingsForm.node, controller_administration_enabled: settingsForm.edge.controller_administration_enabled, reporting: settingsForm.edge.reporting, remote_commands: settingsForm.edge.remote_commands }
	  : {
		  node: settingsForm.node,
		  frp_transport_tls: settingsForm.frp_transport_tls,
		  client_config_comment: settingsForm.client_config_comment,
		  session_ttl: settingsForm.session_ttl,
		  udp_connection_ttl: settingsForm.udp_connection_ttl,
		  controller: settingsForm.controller,
		}
    const data = await api<{ restart_required?: boolean }>('/api/v1/admin/system-settings', {
      method: 'PUT',
	  body: JSON.stringify(payload),
    })
    showToast(data.restart_required ? '已保存，请重启后端' : '系统设置已保存')
    await loadSettings()
  } catch (error) {
    showError(error, '保存失败')
  } finally {
    busy.value = false
  }
}

async function saveRemoteEdgeRuntime(node: EdgeNode) {
  busy.value = true
  try {
    const data = await api<{ delivered: boolean }>(`/api/v1/admin/nodes/${encodeURIComponent(node.node_id)}/runtime-settings`, {
      method: 'PUT',
      body: JSON.stringify(node.capabilities.runtime_settings),
    })
	const runtime = node.capabilities.runtime_settings
	node.name = runtime.tag
	node.public_api_url = runtime.public_api_url
	node.selectable = runtime.selectable
    showToast(data.delivered ? 'Edge 运行参数已实时投递' : 'Edge 当前离线，运行参数已排队')
  } catch (error) {
    showError(error, '修改 Edge 运行参数失败')
  } finally {
    busy.value = false
  }
}

async function generateEnrollmentToken() {
  busy.value = true
  enrollmentToken.value = ''
  try {
	const data = await api<{ enrollment_token: string }>('/api/v1/admin/nodes/enrollment-tokens', { method: 'POST' })
	enrollmentToken.value = data.enrollment_token
	showToast('一次性注册凭证已生成')
  } catch (error) { showError(error, '生成注册凭证失败') } finally { busy.value = false }
}

async function saveEdgeNode(node: EdgeNode) {
  busy.value = true
  try {
    await api(`/api/v1/admin/nodes/${encodeURIComponent(node.node_id)}`, {
      method: 'PUT',
      body: JSON.stringify({ name: node.name, public_api_url: node.public_api_url, selectable: node.selectable }),
    })
    showToast('节点目录设置已保存')
  } catch (error) { showError(error, '节点保存失败') } finally { busy.value = false }
}

async function saveRemoteEdgePermissions(node: EdgeNode) {
  busy.value = true
  try {
    const data = await api<{ delivered: boolean }>(`/api/v1/admin/nodes/${encodeURIComponent(node.node_id)}/remote-permissions`, {
      method: 'PUT',
      body: JSON.stringify({ reporting: node.capabilities.reporting, remote_commands: node.capabilities.remote_commands }),
    })
    showToast(data.delivered ? 'Edge 权限命令已实时投递' : 'Edge 当前离线，权限命令已安全排队')
  } catch (error) {
    showError(error, '修改 Edge 权限失败')
  } finally {
    busy.value = false
  }
}

async function rotateRemoteEdgeAdmin(node: EdgeNode) {
  const form = edgeAdminForms[node.node_id]
  if (!form || form.password !== form.password_confirm) {
    showError(new Error('两次输入的新密码不一致'), '修改 Edge 管理员失败')
    return
  }
  if (!node.connected) {
    showError(new Error('节点离线，管理员密码不会进入离线队列'), '修改 Edge 管理员失败')
    return
  }
  busy.value = true
  try {
    await api(`/api/v1/admin/nodes/${encodeURIComponent(node.node_id)}/admin-credentials`, {
      method: 'POST',
      body: JSON.stringify({ username: form.username, display_name: form.display_name, password: form.password, controller_password: form.controller_password }),
    })
    node.capabilities.admin_username = form.username
    node.capabilities.admin_display_name = form.display_name
    form.password = ''
    form.password_confirm = ''
    form.controller_password = ''
    showToast('Edge 管理员凭据已修改，节点上的旧管理会话已经失效')
  } catch (error) {
    showError(error, '修改 Edge 管理员失败')
  } finally {
    busy.value = false
  }
}

function edgeNodeName(nodeID: string) {
  const node = edgeNodes.value.find((item) => item.node_id === nodeID)
  return node?.name || nodeID
}

async function sendEdgeCommand(nodeID: string, command: string, payload: Record<string, unknown>, scope = 'node') {
  if (!nodeID) throw new Error('请选择边缘节点')
  return api(`/api/v1/admin/nodes/${encodeURIComponent(nodeID)}/commands`, {
    method: 'POST',
    body: JSON.stringify({ command, scope, payload }),
  })
}

async function disconnectEdgeClient(client: EdgeClientPresence) {
  if (!window.confirm(`确认踢出边缘节点 ${edgeNodeName(client.node_id)} 上的客户端 ${client.client_id}？`)) return
  busy.value = true
  try {
    await sendEdgeCommand(client.node_id, 'disconnect_client', {
      token_id: client.token_id,
      client_id: client.client_id,
      reason: 'controller administrator disconnected the client',
    })
    showToast('踢出命令已投递；边缘节点将在本地立即断开并要求客户端重新鉴权')
  } catch (error) {
    showError(error, '踢出客户端失败')
  } finally {
    busy.value = false
  }
}

async function disconnectEdgeConnection(connection: EdgeConnection) {
  if (!connection.can_terminate || connection.protocol !== 'tcp') {
    showToast('该连接不能远程断开')
    return
  }
  if (!window.confirm(`确认断开 ${edgeNodeName(connection.node_id)} 上的连接 ${connection.id}？`)) return
  busy.value = true
  try {
    await sendEdgeCommand(connection.node_id, 'disconnect_connection', { connection_id: connection.id })
    showToast('断开连接命令已投递')
  } catch (error) {
    showError(error, '断开边缘连接失败')
  } finally {
    busy.value = false
  }
}

async function reEnrollEdge() {
  if (!window.confirm('重新注册会签发新的 EDGE 证书；写入 cfg 后需要重启当前服务。继续吗？')) return
  busy.value = true
  try {
    const data = await api<{ node_id: string; certificate_expires_at: string; restart_required: boolean }>('/api/v1/admin/edge/re-enroll', {
      method: 'POST',
      body: JSON.stringify(edgeReEnrollForm),
    })
    edgeReEnrollForm.enrollment_token = ''
    restartNotice.value = `证书已重新签发，有效期至 ${formatTime(data.certificate_expires_at)}；请重启后端以使用新证书。`
    showToast('EDGE 证书已更新')
    await refreshAll()
  } catch (error) {
    showError(error, 'EDGE 重新连接中心失败')
  } finally {
    busy.value = false
  }
}

async function updateEdgeIPBlock(command: 'block_ip' | 'unblock_ip') {
  busy.value = true
  try {
    await sendEdgeCommand(edgeBlockForm.node_id, command, {
      ip: edgeBlockForm.ip,
      reason: edgeBlockForm.reason,
    }, edgeBlockForm.scope)
    showToast(command === 'block_ip' ? 'IP 封禁命令已投递' : 'IP 解封命令已投递')
    if (command === 'block_ip') edgeBlockForm.reason = ''
  } catch (error) {
    showError(error, command === 'block_ip' ? '封禁 IP 失败' : '解封 IP 失败')
  } finally {
    busy.value = false
  }
}

async function queryClientPolicy() {
  busy.value = true
  clientPolicyResult.value = null
  clientDpiStatus.value = null
  try {
    const response = await fetch('/api/v1/client/resource-policy', {
      credentials: 'include',
      cache: 'no-store',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        access_token: bootstrapForm.access_token,
        client_id: bootstrapForm.client_id,
      }),
    })
    const data = await response.json()
    if (!response.ok || data.ok === false) {
      throw new Error(data.error || data.reason || `HTTP ${response.status}`)
    }
    clientPolicyResult.value = data.policy
    clientDpiStatus.value = data.dpi || null
    clientFrpEndpoint.addr = data.frp_server_addr || ''
    clientFrpEndpoint.port = data.frp_server_port || 0
    clientFrpEndpoint.tls = Boolean(data.frp_transport_tls)
    showToast('已获取可用资源')
  } catch (error) {
    showError(error, '查询失败')
  } finally {
    busy.value = false
  }
}

async function copyText(value: string) {
  await navigator.clipboard.writeText(value)
  showToast('已复制')
}

function userName(id: number) {
  return (users.value ?? []).find((user) => user.id === id)?.username ?? `#${id}`
}

function policyForUser(id: number) {
  return (userPolicies.value ?? []).find((policy) => policy.user_id === id)
}

function dpiPolicyForUser(id: number) {
  return (dpiPolicies.value ?? []).find((policy) => policy.user_id === id)
}

function tokensForUser(id: number) {
  return (tokens.value ?? []).filter((token) => token.user_id === id)
}

function clientsForUser(id: number) {
  return (clients.value ?? []).filter((client) => client.user_id === id)
}

function primaryTokenForUser(id: number) {
  return tokensForUser(id)[0]
}

function formatTime(value?: string) {
  if (!value) return '-'
  return new Date(value).toLocaleString()
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 2)} ${units[index]}`
}

function openUserDetail(user: User) {
  selectedUserID.value = user.id
  policyForm.user_id = String(user.id)
  const policy = policyForUser(user.id)
  if (policy) {
    policyForm.port_start = policy.port_start
    policyForm.port_end = policy.port_end
    policyForm.max_ports = policy.max_ports
    policyForm.allowed_protocols = policy.allowed_protocols?.length ? [...policy.allowed_protocols] : []
    policyForm.enabled = policy.enabled
  } else {
    policyForm.port_start = 6001
    policyForm.port_end = 6001
    policyForm.max_ports = 1
    policyForm.allowed_protocols = ['tcp', 'udp']
    policyForm.enabled = true
  }
  loadDpiForm(user.id)
}

function closeUserDetail() {
  selectedUserID.value = null
}

function openCreateUser() {
  Object.assign(userForm, { username: '', display_name: '', password: '', role: 'user' })
  showCreateUser.value = true
}

function closeCreateUser() {
  showCreateUser.value = false
}

function loadDpiForm(userID: number) {
	const policy = dpiPolicyForUser(userID)
	Object.assign(dpiForm, {
    user_id: userID,
    enabled: policy?.enabled ?? false,
    mode: policy?.mode ?? 'monitor',
    enabled_detectors: policy?.enabled_detectors?.length
      ? [...policy.enabled_detectors]
      : ['http', 'tls', 'quic', 'encrypted_tunnel'],
    block_on_any_finding: policy?.block_on_any_finding ?? false,
    allow_http: policy?.allow_http ?? true,
    allow_tls: policy?.allow_tls ?? true,
    allow_quic: policy?.allow_quic ?? true,
    allow_encrypted_tunnel: policy?.allow_encrypted_tunnel ?? true,
    max_inspect_bytes: policy?.max_inspect_bytes ?? 8192,
    temporary_block_ttl_seconds: policy?.temporary_block_ttl_seconds ?? 120,
    encrypted_tunnel_mode: policy?.encrypted_tunnel_mode ?? 'monitor',
	})
}

function startConnectedClientsRefresh() {
	if (connectedClientsTimer !== null) return
	void refreshConnectedClients(true)
	connectedClientsTimer = window.setInterval(() => {
		if (authed.value && activeNav.value === 'clients') {
			void refreshConnectedClients(true)
		}
	}, 10000)
}

function stopConnectedClientsRefresh() {
	if (connectedClientsTimer === null) return
	window.clearInterval(connectedClientsTimer)
	connectedClientsTimer = null
}

watch([authed, activeNav], ([isAuthed, nav]) => {
	if (isAuthed && nav === 'clients') {
		startConnectedClientsRefresh()
		return
	}
	stopConnectedClientsRefresh()
})

onMounted(initialize)
onUnmounted(stopConnectedClientsRefresh)
</script>

<template>
  <main v-if="loading" class="boot-screen">
    <div class="boot-mark">
      <Sparkles :size="28" />
    </div>
    <p>Loading control plane</p>
  </main>

  <main v-else-if="backendMessage" class="auth-shell">
    <section class="auth-panel">
      <div class="brand-row">
        <div class="brand-mark"><Server :size="24" /></div>
        <div>
          <h1>frp control</h1>
          <p>API offline</p>
        </div>
      </div>
      <div class="alert danger">{{ backendMessage }}</div>
      <button class="primary" type="button" @click="initialize">
        <RefreshCw :size="18" />
        重试
      </button>
    </section>
  </main>

  <main v-else-if="!initialized" class="auth-shell">
    <section class="auth-panel setup-panel">
      <div class="brand-row">
        <div class="brand-mark warm"><WandSparkles :size="24" /></div>
        <div>
          <h1>frp control</h1>
          <p>First setup</p>
        </div>
      </div>
      <div v-if="restartNotice" class="alert warning">{{ restartNotice }}</div>
	  <div v-if="configError" class="alert danger">原配置文件无效：{{ configError }}</div>
	  <div class="control-row span-all">
		<button type="button" :class="setupMode === 'controller' ? 'primary' : 'ghost'" @click="setupMode = 'controller'">本地 / 中心服务器</button>
		<button type="button" :class="setupMode === 'edge' ? 'primary' : 'ghost'" @click="setupMode = 'edge'">边缘节点</button>
	  </div>
      <form v-if="setupMode === 'controller'" class="form-grid" @submit.prevent="setupAdmin">
        <label>
          <span>用户名</span>
          <input v-model="setupForm.username" autocomplete="username" />
        </label>
        <label>
          <span>显示名</span>
          <input v-model="setupForm.display_name" />
        </label>
        <label>
          <span>密码</span>
          <input v-model="setupForm.password" type="password" autocomplete="new-password" />
        </label>
        <div class="form-section span-all">MySQL</div>
        <label>
          <span>地址</span>
          <input v-model="setupForm.database.host" />
        </label>
        <label>
          <span>端口</span>
          <input v-model.number="setupForm.database.port" type="number" min="1" />
        </label>
        <label>
          <span>数据库</span>
          <input v-model="setupForm.database.database" />
        </label>
        <label>
          <span>数据库用户</span>
          <input v-model="setupForm.database.username" autocomplete="off" />
        </label>
        <label class="span-all">
          <span>数据库密码</span>
          <input v-model="setupForm.database.password" type="password" autocomplete="off" />
        </label>
        <button class="primary" type="submit" :disabled="busy">
          <ShieldCheck :size="18" />
          验证数据库并初始化
        </button>
      </form>
	  <form v-else class="form-grid" @submit.prevent="setupEdge">
		<label><span>管理用户名</span><input v-model="edgeSetupForm.username" autocomplete="username" /></label>
		<label><span>显示名</span><input v-model="edgeSetupForm.display_name" /></label>
		<label class="span-all"><span>管理密码</span><input v-model="edgeSetupForm.password" type="password" autocomplete="new-password" /></label>
		<div class="form-section span-all">中心节点注册</div>
		<label><span>节点名称</span><input v-model="edgeSetupForm.node_name" placeholder="上海边缘节点" /></label>
		<label><span>中心 HTTPS API 地址</span><input v-model="edgeSetupForm.controller_address" placeholder="https://controller.example.com/api" /></label>
		<label class="span-all"><span>一次性注册凭证</span><textarea v-model="edgeSetupForm.enrollment_token" rows="4" /></label>
		<button class="primary" type="submit" :disabled="busy"><ShieldCheck :size="18" />验证中心并注册</button>
	  </form>
    </section>
  </main>

  <main v-else-if="databaseRepairRequired" class="auth-shell">
    <section class="auth-panel setup-panel">
      <div class="brand-row">
        <div class="brand-mark warm"><WandSparkles :size="24" /></div>
        <div>
          <h1>frp control</h1>
          <p>数据库连接异常</p>
        </div>
      </div>
      <div class="alert danger">系统已经初始化过，但当前数据库无法连接。请使用第一次初始化时的管理员账号和密码修改数据库配置。</div>
      <form class="form-grid" @submit.prevent="repairDatabase">
        <label>
          <span>初始管理员账号</span>
          <input v-model="repairForm.username" autocomplete="username" />
        </label>
        <label>
          <span>初始管理员密码</span>
          <input v-model="repairForm.password" type="password" autocomplete="current-password" />
        </label>
        <div class="form-section span-all">MySQL</div>
        <label>
          <span>地址</span>
          <input v-model="repairForm.database.host" />
        </label>
        <label>
          <span>端口</span>
          <input v-model.number="repairForm.database.port" type="number" min="1" />
        </label>
        <label>
          <span>数据库</span>
          <input v-model="repairForm.database.database" />
        </label>
        <label>
          <span>数据库用户</span>
          <input v-model="repairForm.database.username" autocomplete="off" />
        </label>
        <label class="span-all">
          <span>数据库密码</span>
          <input v-model="repairForm.database.password" type="password" autocomplete="off" />
        </label>
        <button class="primary" type="submit" :disabled="busy">
          <ShieldCheck :size="18" />
          验证并保存数据库配置
        </button>
      </form>
    </section>
  </main>

  <main v-else-if="!authed" class="auth-shell">
    <section class="auth-panel">
      <div class="brand-row">
        <div class="brand-mark"><LockKeyhole :size="24" /></div>
        <div>
          <h1>frp control</h1>
          <p>Admin panel</p>
        </div>
      </div>
      <form class="form-grid" @submit.prevent="login">
        <label>
          <span>用户名</span>
          <input v-model="loginForm.username" autocomplete="username" />
        </label>
        <label>
          <span>密码</span>
          <input v-model="loginForm.password" type="password" autocomplete="current-password" />
        </label>
        <button class="primary" type="submit" :disabled="busy">
          <ShieldCheck :size="18" />
          登录
        </button>
      </form>
    </section>
  </main>

  <main v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand-row compact">
        <div class="brand-mark"><Sparkles :size="22" /></div>
        <div>
          <h1>frp control</h1>
          <p>{{ me?.username }}</p>
        </div>
      </div>
      <nav class="nav-list">
        <button
		  v-for="item in visibleNavItems"
          :key="item.id"
          type="button"
          :class="{ active: activeNav === item.id }"
          @click="activeNav = item.id"
        >
          <component :is="item.icon" :size="18" />
          {{ item.label }}
        </button>
      </nav>
      <button class="ghost full" type="button" @click="logout">
        <LogOut :size="18" />
        退出
      </button>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div>
          <p class="eyebrow">Server Panel</p>
		  <h2>{{ visibleNavItems.find((item) => item.id === activeNav)?.label }}</h2>
        </div>
        <button class="ghost" type="button" @click="refreshAll">
          <RefreshCw :size="18" />
          刷新
        </button>
      </header>
      <div v-if="lastError" class="alert danger page-alert">{{ lastError }}</div>

      <section v-if="activeNav === 'overview'" class="page-stack">
        <div class="stats-grid">
          <article class="stat-card coral">
            <Users :size="22" />
            <span>活跃用户</span>
            <strong>{{ activeUsers }}</strong>
          </article>
          <article class="stat-card mint">
            <KeyRound :size="22" />
            <span>可用凭证</span>
            <strong>{{ activeTokens }}</strong>
          </article>
          <article class="stat-card blue">
            <Monitor :size="22" />
            <span>活跃客户端</span>
            <strong>{{ activeClients }}</strong>
          </article>
          <article class="stat-card ink">
            <Ban :size="22" />
            <span>封禁项</span>
            <strong>{{ banTotal }}</strong>
          </article>
        </div>
        <section class="panel">
          <div class="panel-head">
            <h3>最近凭证</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>名称</th>
                  <th>用户</th>
                  <th>前缀</th>
                  <th>代理数</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="token in safeTokens.slice(0, 6)" :key="token.id">
                  <td>{{ token.name }}</td>
                  <td>{{ userName(token.user_id) }}</td>
                  <td><code>{{ token.token_prefix }}</code></td>
                  <td>{{ token.max_proxy_count }}</td>
                  <td><span class="pill" :class="token.status">{{ token.status }}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'users'" class="page-stack">
        <section class="panel">
          <div class="panel-head">
            <h3>用户列表</h3>
            <button class="primary" type="button" @click="openCreateUser">
              <Plus :size="18" />
              新建用户
            </button>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>用户名</th>
                  <th>显示名</th>
                  <th>角色</th>
                  <th>服务端端口</th>
                  <th>数量</th>
                  <th>API token</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="user in safeUsers" :key="user.id">
                  <td>{{ user.id }}</td>
                  <td>{{ user.username }}</td>
                  <td>{{ user.display_name }}</td>
                  <td>{{ user.role }}</td>
                  <td>
                    <code v-if="policyForUser(user.id)">
                      {{ policyForUser(user.id)?.port_start }}-{{ policyForUser(user.id)?.port_end }}
                    </code>
                    <span v-else class="muted-text">未配置</span>
                  </td>
                  <td>{{ policyForUser(user.id)?.max_ports ?? '-' }}</td>
                  <td>
                    <code v-if="primaryTokenForUser(user.id)">{{ primaryTokenForUser(user.id)?.token_prefix }}</code>
                    <span v-else class="muted-text">未生成</span>
                  </td>
                  <td><span class="pill" :class="user.status">{{ user.status }}</span></td>
                  <td class="actions">
                    <button class="icon-button" type="button" title="详情" @click="openUserDetail(user)">
                      <Info :size="16" />
                    </button>
                    <button class="icon-button danger" type="button" title="删除用户" :disabled="busy || me?.id === user.id" @click="deleteUser(user)">
                      <Trash2 :size="16" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'clients'" class="page-stack">
        <section class="panel">
          <div class="panel-head">
            <h3>已连接客户端</h3>
            <button class="ghost" type="button" @click="refreshConnectedClients()">
              <RefreshCw :size="16" />
              刷新
            </button>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Client ID</th>
                  <th>用户</th>
                  <th>Token</th>
                  <th>frpc IP</th>
                  <th>最后心跳</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="client in safeConnectedClients" :key="client.id">
                  <td>{{ client.id }}</td>
                  <td><code>{{ client.client_id }}</code></td>
                  <td>{{ userName(client.user_id) }}</td>
                  <td>#{{ client.token_id }}</td>
                  <td><code>{{ client.frpc_addr || '-' }}</code></td>
                  <td>{{ formatTime(client.last_seen_at) }}</td>
                  <td><span class="pill" :class="client.status">{{ client.status }}</span></td>
                  <td class="actions">
                    <button class="icon-button danger" type="button" title="远程关闭 frpc" :disabled="busy" @click="sendClientCommand(client, 'stop_frpc')">
                      <X :size="16" />
                    </button>
                    <button class="icon-button" type="button" title="弹窗提醒" :disabled="busy" @click="sendClientCommand(client, 'show_warning')">
                      <Info :size="16" />
                    </button>
                    <button class="icon-button" type="button" title="要求重新鉴权" :disabled="busy" @click="sendClientCommand(client, 'reauth')">
                      <RefreshCw :size="16" />
                    </button>
                    <button v-if="client.status !== 'banned'" class="icon-button danger" type="button" title="封禁" @click="setStatus('clients', client.id, 'ban')">
                      <Ban :size="16" />
                    </button>
                    <button v-else class="icon-button" type="button" title="解封" @click="setStatus('clients', client.id, 'unban')">
                      <RotateCcw :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!safeConnectedClients.length">
                  <td colspan="8" class="muted-text">当前没有 60 秒内保持 HTTPS 心跳的客户端。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
        <section v-if="deploymentMode === 'controller'" class="panel">
          <div class="panel-head">
            <div>
              <h3>边缘节点客户端</h3>
              <p>由 Edge 心跳聚合上报；中心下发踢出命令后由对应节点本地执行。</p>
            </div>
            <button class="ghost" type="button" @click="refreshEdgeClients()"><RefreshCw :size="16" />刷新</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>节点</th><th>Client ID</th><th>用户</th><th>Token</th><th>frpc</th><th>最后上报</th><th>操作</th></tr></thead>
              <tbody>
                <tr v-for="client in edgeClients" :key="`${client.node_id}:${client.token_id}:${client.client_id}`">
                  <td>{{ edgeNodeName(client.node_id) }}</td>
                  <td><code>{{ client.client_id }}</code></td>
                  <td>{{ userName(client.user_id) }}</td>
                  <td>#{{ client.token_id }}</td>
                  <td><span class="pill" :class="client.frpc_running ? 'active' : 'banned'">{{ client.frpc_running ? '运行中' : '未运行' }}</span></td>
                  <td>{{ formatTime(client.last_seen_at) }}</td>
                  <td><button class="icon-button danger" type="button" title="通过边缘节点踢出客户端" :disabled="busy" @click="disconnectEdgeClient(client)"><X :size="16" /></button></td>
                </tr>
                <tr v-if="!edgeClients.length"><td colspan="7" class="muted-text">最近 90 秒没有边缘节点上报在线客户端。</td></tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'clientHistory'" class="page-stack">
        <section class="panel">
          <div class="panel-head">
            <h3>历史客户端</h3>
            <button class="ghost" type="button" @click="refreshAll">
              <RefreshCw :size="16" />
              刷新
            </button>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Client ID</th>
                  <th>用户</th>
                  <th>Token</th>
                  <th>frpc IP</th>
                  <th>最后心跳</th>
                  <th>状态</th>
                  <th>原因</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="client in clients" :key="client.id">
                  <td>#{{ client.id }}</td>
                  <td><code>{{ client.client_id }}</code></td>
                  <td>{{ userName(client.user_id) }}</td>
                  <td>#{{ client.token_id }}</td>
                  <td><code>{{ client.frpc_addr || '-' }}</code></td>
                  <td>{{ formatTime(client.last_seen_at) }}</td>
                  <td><span class="pill" :class="client.status">{{ client.status }}</span></td>
                  <td>{{ client.ban_reason || '-' }}</td>
                  <td class="actions">
                    <button v-if="client.status !== 'banned'" class="icon-button danger" type="button" title="封禁客户端" :disabled="busy" @click="setStatus('clients', client.id, 'ban')">
                      <Ban :size="16" />
                    </button>
                    <button v-else class="icon-button" type="button" title="解封客户端" :disabled="busy" @click="setStatus('clients', client.id, 'unban')">
                      <RotateCcw :size="16" />
                    </button>
                    <button class="icon-button danger" type="button" title="删除客户端记录" :disabled="busy" @click="deleteClient(client)">
                      <Trash2 :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!clients.length">
                  <td colspan="9" class="muted-text">暂无历史客户端记录。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'connections'" class="page-stack">
        <section class="panel">
          <div class="panel-head">
            <h3>连接列表</h3>
            <button class="ghost" type="button" @click="refreshConnections()">
              <RefreshCw :size="18" />
              刷新
            </button>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>协议</th>
                  <th>用户</th>
                  <th>隧道</th>
                  <th>服务端端口</th>
                  <th>入站 IP</th>
                  <th>客户端 IP</th>
                  <th>最后活动</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="connection in connections" :key="connection.id">
                  <td><span class="pill active">{{ connection.protocol.toUpperCase() }}</span></td>
                  <td>{{ userName(connection.user_id) }}</td>
                  <td>{{ connection.proxy_name }} / {{ connection.proxy_type }}</td>
                  <td>{{ connection.remote_port || '-' }}</td>
                  <td><code>{{ connection.inbound_addr || connection.inbound_ip || '-' }}</code></td>
                  <td><code>{{ connection.client_addr || connection.client_id || '-' }}</code></td>
                  <td>{{ new Date(connection.last_seen_at).toLocaleString() }}</td>
                  <td class="actions">
                    <button
                      v-if="connection.protocol === 'tcp'"
                      class="icon-button danger"
                      type="button"
                      title="断开 TCP 连接"
                      :disabled="busy"
                      @click="disconnectConnection(connection)"
                    >
                      <X :size="16" />
                    </button>
                    <button
                      class="icon-button danger"
                      type="button"
                      title="拉黑入站 IP"
                      :disabled="busy || !connection.inbound_ip"
                      @click="blockConnectionIP(connection)"
                    >
                      <Ban :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!connections.length">
                  <td colspan="8" class="muted-text">当前没有活跃连接。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section v-if="deploymentMode === 'controller'" class="panel">
          <div class="panel-head">
            <div>
              <h3>边缘节点连接</h3>
              <p>由开启“连接详情”上报的 EDGE 通过 mTLS 心跳同步。</p>
            </div>
            <button class="ghost" type="button" @click="refreshEdgeTelemetry()"><RefreshCw :size="18" />刷新上报</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>节点</th><th>协议</th><th>Client</th><th>隧道</th><th>端口</th><th>入站地址</th><th>最后活动</th><th>操作</th></tr></thead>
              <tbody>
                <tr v-for="connection in edgeConnections" :key="`${connection.node_id}:${connection.id}`">
                  <td>{{ edgeNodeName(connection.node_id) }}</td>
                  <td><span class="pill active">{{ connection.protocol.toUpperCase() }}</span></td>
                  <td><code>{{ connection.client_id || '-' }}</code></td>
                  <td>{{ connection.proxy_name }} / {{ connection.proxy_type }}</td>
                  <td>{{ connection.remote_port || '-' }}</td>
                  <td><code>{{ connection.inbound_addr || connection.inbound_ip || '-' }}</code></td>
                  <td>{{ formatTime(connection.last_seen_at) }}</td>
                  <td><button v-if="connection.can_terminate" class="icon-button danger" type="button" title="通过 EDGE 断开 TCP 连接" :disabled="busy" @click="disconnectEdgeConnection(connection)"><X :size="16" /></button></td>
                </tr>
                <tr v-if="!edgeConnections.length"><td colspan="8" class="muted-text">暂无 EDGE 连接快照，或节点关闭了连接详情上报。</td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <section v-if="deploymentMode === 'controller'" class="panel">
          <div class="panel-head"><div><h3>边缘节点流量统计</h3><p>数值为 EDGE 当前服务进程启动后的累计采样。</p></div></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>节点</th><th>入站</th><th>出站</th><th>入站采样</th><th>出站采样</th><th>进程启动</th><th>采集时间</th></tr></thead>
              <tbody>
                <tr v-for="traffic in edgeTraffic" :key="traffic.node_id">
                  <td>{{ edgeNodeName(traffic.node_id) }}</td><td>{{ formatBytes(traffic.bytes_inbound) }}</td><td>{{ formatBytes(traffic.bytes_outbound) }}</td>
                  <td>{{ traffic.samples_inbound }}</td><td>{{ traffic.samples_outbound }}</td><td>{{ formatTime(traffic.started_at) }}</td><td>{{ formatTime(traffic.captured_at) }}</td>
                </tr>
                <tr v-if="!edgeTraffic.length"><td colspan="7" class="muted-text">暂无 EDGE 流量上报。</td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <section v-if="deploymentMode === 'controller'" class="panel">
          <div class="panel-head"><div><h3>边缘节点运行日志</h3><p>仅显示开启运行日志上报的节点最近 100 条可靠事件。</p></div></div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>时间</th><th>节点</th><th>日志</th></tr></thead>
              <tbody>
                <tr v-for="item in edgeRuntimeLogs" :key="item.event_id"><td>{{ formatTime(item.payload?.created_at || item.created_at) }}</td><td>{{ edgeNodeName(item.node_id) }}</td><td><code>{{ item.payload?.message || '-' }}</code></td></tr>
                <tr v-if="!edgeRuntimeLogs.length"><td colspan="3" class="muted-text">暂无 EDGE 运行日志。</td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h3>入站 IP 黑名单</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>原因</th>
                  <th>时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in blockedInboundIPs" :key="item.ip">
                  <td><code>{{ item.ip }}</code></td>
                  <td>{{ item.reason || '-' }}</td>
                  <td>{{ new Date(item.created_at).toLocaleString() }}</td>
                  <td class="actions">
                    <button class="icon-button" type="button" title="解除拉黑" :disabled="busy" @click="unblockInboundIP(item.ip)">
                      <RotateCcw :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!blockedInboundIPs.length">
                  <td colspan="4" class="muted-text">暂无被拉黑的入站 IP。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'bans'" class="page-stack">
        <section class="panel">
          <div class="panel-head">
            <h3>封禁概览</h3>
            <button class="ghost" type="button" @click="refreshAll">
              <RefreshCw :size="18" />
              刷新
            </button>
          </div>
          <div class="stats-grid compact-stats">
            <article class="stat-card ink">
              <Users :size="20" />
              <span>用户</span>
              <strong>{{ bannedUserList.length }}</strong>
            </article>
            <article class="stat-card coral">
              <KeyRound :size="20" />
              <span>凭证</span>
              <strong>{{ bannedTokenList.length }}</strong>
            </article>
            <article class="stat-card blue">
              <Monitor :size="20" />
              <span>客户端</span>
              <strong>{{ bannedClientList.length }}</strong>
            </article>
            <article class="stat-card mint">
              <Ban :size="20" />
              <span>入站 IP</span>
              <strong>{{ blockedInboundIPs.length }}</strong>
            </article>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h3>封禁用户</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>用户名</th>
                  <th>显示名</th>
                  <th>原因</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="user in bannedUserList" :key="user.id">
                  <td>#{{ user.id }}</td>
                  <td>{{ user.username }}</td>
                  <td>{{ user.display_name || '-' }}</td>
                  <td>{{ user.ban_reason || '-' }}</td>
                  <td class="actions">
                    <button class="icon-button" type="button" title="解封用户" :disabled="busy" @click="setStatus('users', user.id, 'unban')">
                      <RotateCcw :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!bannedUserList.length">
                  <td colspan="5" class="muted-text">暂无封禁用户。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h3>封禁凭证</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>名称</th>
                  <th>用户</th>
                  <th>前缀</th>
                  <th>原因</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="token in bannedTokenList" :key="token.id">
                  <td>#{{ token.id }}</td>
                  <td>{{ token.name }}</td>
                  <td>{{ userName(token.user_id) }}</td>
                  <td><code>{{ token.token_prefix }}</code></td>
                  <td>{{ token.ban_reason || '-' }}</td>
                  <td class="actions">
                    <button class="icon-button" type="button" title="解封凭证" :disabled="busy" @click="setStatus('tokens', token.id, 'unban')">
                      <RotateCcw :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!bannedTokenList.length">
                  <td colspan="6" class="muted-text">暂无封禁凭证。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h3>封禁客户端</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Client ID</th>
                  <th>用户</th>
                  <th>Token</th>
                  <th>frpc IP</th>
                  <th>原因</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="client in bannedClientList" :key="client.id">
                  <td>#{{ client.id }}</td>
                  <td><code>{{ client.client_id }}</code></td>
                  <td>{{ userName(client.user_id) }}</td>
                  <td>#{{ client.token_id }}</td>
                  <td><code>{{ client.frpc_addr || '-' }}</code></td>
                  <td>{{ client.ban_reason || '-' }}</td>
                  <td class="actions">
                    <button class="icon-button" type="button" title="解封客户端" :disabled="busy" @click="setStatus('clients', client.id, 'unban')">
                      <RotateCcw :size="16" />
                    </button>
                    <button class="icon-button danger" type="button" title="删除客户端记录" :disabled="busy" @click="deleteClient(client)">
                      <Trash2 :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!bannedClientList.length">
                  <td colspan="7" class="muted-text">暂无封禁客户端。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h3>入站 IP 黑名单</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>原因</th>
                  <th>时间</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="item in blockedInboundIPs" :key="item.ip">
                  <td><code>{{ item.ip }}</code></td>
                  <td>{{ item.reason || '-' }}</td>
                  <td>{{ formatTime(item.created_at) }}</td>
                  <td class="actions">
                    <button class="icon-button" type="button" title="解除拉黑" :disabled="busy" @click="unblockInboundIP(item.ip)">
                      <RotateCcw :size="16" />
                    </button>
                  </td>
                </tr>
                <tr v-if="!blockedInboundIPs.length">
                  <td colspan="4" class="muted-text">暂无被拉黑的入站 IP。</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'dpi'" class="page-stack">
        <section class="panel">
          <div class="panel-head">
            <h3>DPI Gateway Users</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Mode</th>
                  <th>HTTP</th>
                  <th>TLS</th>
                  <th>QUIC</th>
                  <th>SS</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="user in safeUsers.filter((item) => dpiPolicyForUser(item.id)?.enabled)" :key="user.id">
                  <td>{{ user.username }}</td>
                  <td><span class="pill active">{{ dpiPolicyForUser(user.id)?.mode || 'monitor' }}</span></td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_http ?? true ? 'allow' : 'block' }}</td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_tls ?? true ? 'allow' : 'block' }}</td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_quic ?? true ? 'allow' : 'block' }}</td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_encrypted_tunnel ?? true ? 'allow' : 'block' }}</td>
                  <td><button class="ghost" type="button" @click="loadDpiForm(user.id)">Detail Config</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>

        <section v-if="dpiForm.user_id" class="panel">
          <div class="panel-head">
            <h3>DPI Detail Config - {{ userName(dpiForm.user_id) }}</h3>
          </div>
          <form class="form-grid dpi-config-grid" @submit.prevent="saveDpiPolicy()">
            <label>
              <span>Block mode</span>
              <select v-model="dpiForm.mode">
                <option value="monitor">monitor only</option>
                <option value="block">block disallowed traffic</option>
              </select>
            </label>
            <label>
              <span>Max inspect bytes</span>
              <input v-model.number="dpiForm.max_inspect_bytes" type="number" min="512" max="65536" />
            </label>
            <div class="protocol-checks span-all">
              <span>Detectors</span>
              <label v-for="detector in dpiDetectorOptions" :key="detector.id" class="protocol-check">
                <input v-model="dpiForm.enabled_detectors" type="checkbox" :value="detector.id" />
                <span>{{ detector.label }}</span>
              </label>
            </div>
            <div class="protocol-checks span-all">
              <span>Allowed traffic. Unchecked means block when detected.</span>
              <label class="protocol-check"><input v-model="dpiForm.allow_http" type="checkbox" /><span>HTTP</span></label>
              <label class="protocol-check"><input v-model="dpiForm.allow_tls" type="checkbox" /><span>TLS</span></label>
              <label class="protocol-check"><input v-model="dpiForm.allow_quic" type="checkbox" /><span>QUIC</span></label>
              <label class="protocol-check"><input v-model="dpiForm.allow_encrypted_tunnel" type="checkbox" /><span>SS / encrypted tunnel</span></label>
            </div>
            <button class="primary" type="submit" :disabled="busy">
              <ShieldCheck :size="18" />
              Save Block Rules
            </button>
          </form>
        </section>

        <section class="panel">
          <div class="panel-head">
            <h3>DPI Hit Details</h3>
            <button class="ghost" type="button" @click="refreshAll">
              <RefreshCw :size="18" />
              Refresh
            </button>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Node</th>
                  <th>User</th>
                  <th>Client IP</th>
                  <th>Proxy</th>
                  <th>Rule</th>
                  <th>Target</th>
                  <th>Action</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="event in dpiEvents" :key="event.id">
                  <td>{{ new Date(event.created_at).toLocaleString() }}</td>
                  <td>{{ event.node_id ? edgeNodeName(event.node_id) : 'controller' }}</td>
                  <td>{{ event.username || userName(event.user_id) }}</td>
                  <td><code>{{ event.remote_addr || '-' }}</code></td>
                  <td>{{ event.proxy_name }} / {{ event.proxy_type }}</td>
                  <td>{{ event.detector }} {{ event.protocol ? `(${event.protocol})` : '' }}</td>
                  <td>{{ event.host || event.sni || event.target_ip || '-' }}</td>
                  <td><span class="pill" :class="event.action === 'block' ? 'banned' : 'active'">{{ event.action }}</span></td>
                  <td>{{ event.reason || event.summary || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'bootstrap'" class="split-page">
        <section class="panel side-panel">
          <div class="panel-head">
            <h3>请求</h3>
          </div>
          <form class="form-grid" @submit.prevent="runBootstrap">
            <label><span>Access token</span><input v-model="bootstrapForm.access_token" /></label>
            <label><span>Client ID</span><input v-model="bootstrapForm.client_id" /></label>
            <label><span>版本</span><input v-model="bootstrapForm.client_version" /></label>
            <button class="ghost" type="button" :disabled="busy" @click="queryClientPolicy">
              <ShieldCheck :size="18" />
              查询可用范围
            </button>
            <div v-if="clientPolicyResult" class="resource-hint span-all">
              <CheckCircle2 :size="17" />
              <span>
                可用端口 {{ clientPolicyResult.port_start }}-{{ clientPolicyResult.port_end }}，
                最多 {{ clientPolicyResult.max_ports }} 个；
                协议 {{ clientPolicyResult.allowed_protocols?.join(', ') || '未启用' }}；
                frps {{ clientFrpEndpoint.addr }}:{{ clientFrpEndpoint.port }}
              </span>
            </div>
            <div v-if="clientDpiStatus" class="resource-hint span-all">
              <ShieldCheck :size="17" />
              <span>
                DPI {{ clientDpiStatus.enabled ? clientDpiStatus.mode : 'disabled' }};
                blocked {{ clientDpiStatus.blocked_traffic_types?.join(', ') || 'none' }};
                detectors {{ clientDpiStatus.enabled_detectors?.join(', ') || 'none' }}
              </span>
            </div>
            <label class="span-all">
              <span>Proxies JSON</span>
              <textarea v-model="bootstrapForm.proxies" rows="12" />
            </label>
            <button class="primary" type="submit" :disabled="busy"><Cable :size="18" />请求配置</button>
          </form>
        </section>
        <section class="panel">
          <div class="panel-head">
            <h3>结果</h3>
          </div>
          <div v-if="bootstrapResult" class="result-box" :class="{ failed: !bootstrapResult.ok }">
            <div class="result-status">
              <span class="pill" :class="bootstrapResult.ok ? 'active' : 'banned'">
                {{ bootstrapResult.ok ? 'allowed' : bootstrapResult.status }}
              </span>
              <code v-if="bootstrapResult.lease_id">{{ bootstrapResult.lease_id }}</code>
            </div>
            <p v-if="bootstrapResult.reason">{{ bootstrapResult.reason }}</p>
            <textarea v-if="bootstrapResult.frpc_config" :value="bootstrapResult.frpc_config" rows="18" readonly />
            <button v-if="bootstrapResult.frpc_config" class="ghost" type="button" @click="copyText(bootstrapResult.frpc_config)">
              <Copy :size="18" />
              复制配置
            </button>
          </div>
          <div v-else class="empty-state">
            <Cable :size="30" />
            <span>等待请求</span>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'settings'" class="split-page">
        <section class="panel side-panel">
          <div class="panel-head">
			<h3>{{ deploymentMode === 'edge' ? '边缘节点权限' : 'frp 与中心节点' }}</h3>
          </div>
		  <form v-if="deploymentMode === 'controller'" class="form-grid" @submit.prevent="saveSettings">
            <label>
			  <span>节点标签</span>
			  <input v-model="settingsForm.node.tag" />
            </label>
            <label>
			  <span>公开 API URL</span>
			  <input v-model="settingsForm.node.public_api_url" placeholder="https://controller.example.com/api" />
            </label>
			<label><span>frps 对外地址</span><input v-model="settingsForm.node.frp_advertise_addr" placeholder="公网 IP 或域名" /></label>
			<label><span>frps 控制端口</span><input v-model.number="settingsForm.node.frp_bind_port" type="number" min="1" max="65535" /></label>
			<label><span>可用端口起始</span><input v-model.number="settingsForm.node.port_range_start" type="number" min="1" max="65535" /></label>
			<label><span>可用端口结束</span><input v-model.number="settingsForm.node.port_range_end" type="number" min="1" max="65535" /></label>
			<p class="span-all">中心节点始终包含在客户端节点目录中；Edge 节点可单独控制是否允许选择。</p>
            <label>
              <span>配置注释</span>
              <input v-model="settingsForm.client_config_comment" />
            </label>
            <label>
              <span>Admin token TTL</span>
              <input v-model="settingsForm.session_ttl" placeholder="1h" />
            </label>
            <label>
              <span>UDP 连接超时</span>
              <input v-model="settingsForm.udp_connection_ttl" placeholder="10s" />
            </label>
            <label class="toggle-row">
              <input v-model="settingsForm.frp_transport_tls" type="checkbox" />
              <span>客户端配置启用 frp transport TLS</span>
            </label>
			<div class="form-section span-all">中心节点</div>
			<label class="toggle-row span-all"><input v-model="settingsForm.controller.edge_access_enabled" type="checkbox" /><span>允许边缘节点接入</span></label>
			<label><span>mTLS 监听地址</span><input v-model="settingsForm.controller.listen_addr" placeholder="0.0.0.0:9443" /></label>
			<label><span>mTLS 对外地址</span><input v-model="settingsForm.controller.public_address" placeholder="controller.example.com:9443" /></label>
			<label><span>控制面心跳间隔（秒）</span><input v-model.number="settingsForm.controller.heartbeat_interval_seconds" type="number" min="2" max="60" /></label>
            <button class="primary" type="submit" :disabled="busy">
              <ShieldCheck :size="18" />
              保存设置
            </button>
          </form>
		  <form v-else class="form-grid" @submit.prevent="saveSettings">
			<div class="form-section span-all">本节点 FRP 与端口池</div>
			<label><span>节点标签</span><input v-model="settingsForm.node.tag" /></label>
			<label><span>公开 API URL</span><input v-model="settingsForm.node.public_api_url" placeholder="https://edge.example.com/api" /></label>
			<label><span>frps 对外地址</span><input v-model="settingsForm.node.frp_advertise_addr" placeholder="公网 IP 或域名" /></label>
			<label><span>frps 控制端口</span><input v-model.number="settingsForm.node.frp_bind_port" type="number" min="1" max="65535" /></label>
			<label><span>可用端口起始</span><input v-model.number="settingsForm.node.port_range_start" type="number" min="1" max="65535" /></label>
			<label><span>可用端口结束</span><input v-model.number="settingsForm.node.port_range_end" type="number" min="1" max="65535" /></label>
			<label class="toggle-row span-all"><input v-model="settingsForm.node.selectable" type="checkbox" /><span>建议中心允许客户端选择本节点（中心目录可覆盖）</span></label>
			<div class="form-section span-all">中心远程管理</div>
			<label class="toggle-row span-all"><input v-model="settingsForm.edge.controller_administration_enabled" type="checkbox" /><span>允许中心修改本节点权限和管理员凭据</span></label>
			<p class="danger-text span-all">此开关只能在本节点面板修改。开启后，中心可以调整下方权限，并在节点在线时通过 mTLS 修改本地管理员用户名和密码。</p>
			<div class="form-section span-all">信息上报</div>
			<label class="toggle-row"><input v-model="settingsForm.edge.reporting.client_presence" type="checkbox" /><span>客户端在线状态</span></label>
			<label class="toggle-row"><input v-model="settingsForm.edge.reporting.connections" type="checkbox" /><span>连接详情</span></label>
			<label class="toggle-row"><input v-model="settingsForm.edge.reporting.traffic_statistics" type="checkbox" /><span>流量统计</span></label>
			<label class="toggle-row"><input v-model="settingsForm.edge.reporting.dpi_events" type="checkbox" /><span>DPI 事件</span></label>
			<label class="toggle-row"><input v-model="settingsForm.edge.reporting.runtime_logs" type="checkbox" /><span>运行日志</span></label>
			<div class="form-section span-all">接受中心命令</div>
			<label class="toggle-row"><input v-model="settingsForm.edge.remote_commands.disconnect_client" type="checkbox" /><span>踢出客户端</span></label>
			<label class="toggle-row"><input v-model="settingsForm.edge.remote_commands.disconnect_connection" type="checkbox" /><span>断开连接</span></label>
			<label class="toggle-row"><input v-model="settingsForm.edge.remote_commands.block_ip" type="checkbox" /><span>封禁 IP</span></label>
			<label class="toggle-row"><input v-model="settingsForm.edge.remote_commands.change_runtime_settings" type="checkbox" /><span>修改运行参数</span></label>
			<button class="primary" type="submit" :disabled="busy"><ShieldCheck :size="18" />保存节点权限</button>
		  </form>
        </section>
        <section class="panel">
          <div class="panel-head">
			<h3>{{ deploymentMode === 'edge' ? '中心连接' : '节点注册' }}</h3>
          </div>
		  <template v-if="deploymentMode === 'controller'">
			<div class="result-box">
			  <p>首次注册走当前面板的 HTTPS API；注册成功后 Edge 自动切换到独立 mTLS 地址。凭证明文保存在中心数据库，十分钟内有效且只能使用一次。</p>
			  <button class="primary" type="button" :disabled="busy || !settingsForm.controller.edge_access_enabled" @click="generateEnrollmentToken"><KeyRound :size="18" />生成一次性注册凭证</button>
			  <textarea v-if="enrollmentToken" :value="enrollmentToken" rows="7" readonly />
			  <button v-if="enrollmentToken" class="ghost" type="button" @click="copyText(enrollmentToken)"><Copy :size="16" />复制</button>
			</div>
			<div class="result-box">
			  <h4>客户端节点目录</h4>
			  <p>来源地址用于识别节点；API URL 请填写客户端实际可访问的完整反代基础地址。</p>
			  <div v-if="edgeNodes.length === 0" class="empty-state">暂无已注册边缘节点</div>
			  <div v-for="node in edgeNodes" :key="node.node_id" class="form-grid">
				<div class="span-all"><span class="pill" :class="node.connected ? 'active' : 'banned'">{{ node.connected ? 'mTLS 在线' : '离线' }}</span> <span class="pill" :class="node.capabilities.controller_administration_enabled ? 'active' : 'banned'">{{ node.capabilities.controller_administration_enabled ? '已授权远程管理' : '未授权远程管理' }}</span></div>
				<label><span>节点标签</span><input v-model="node.name" /></label>
				<label><span>连接来源</span><input :value="node.last_remote_addr || '-'" readonly /></label>
				<label class="span-all"><span>公开 API URL</span><input v-model="node.public_api_url" placeholder="https://edge.example.com/api" /></label>
				<label class="toggle-row span-all"><input v-model="node.selectable" type="checkbox" /><span>允许客户端选择此节点</span></label>
				<button class="ghost" type="button" :disabled="busy" @click="saveEdgeNode(node)">保存节点目录</button>
				<template v-if="node.capabilities.controller_administration_enabled">
				  <div class="form-section span-all">中心远程修改 Edge 权限</div>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.client_presence" type="checkbox" /><span>上报客户端状态</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.connections" type="checkbox" /><span>上报连接详情</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.traffic_statistics" type="checkbox" /><span>上报流量统计</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.dpi_events" type="checkbox" /><span>上报 DPI 事件</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.runtime_logs" type="checkbox" /><span>上报运行日志</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.disconnect_client" type="checkbox" /><span>允许踢客户端</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.disconnect_connection" type="checkbox" /><span>允许断开连接</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.block_ip" type="checkbox" /><span>允许封禁 IP</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.change_runtime_settings" type="checkbox" /><span>允许修改运行参数</span></label>
				  <button class="ghost" type="button" :disabled="busy" @click="saveRemoteEdgePermissions(node)">下发权限设置</button>
				  <template v-if="node.capabilities.remote_commands.change_runtime_settings">
					<div class="form-section span-all">中心远程修改 Edge 运行参数</div>
					<label><span>节点标签</span><input v-model="node.capabilities.runtime_settings.tag" /></label>
					<label><span>公开 API URL</span><input v-model="node.capabilities.runtime_settings.public_api_url" /></label>
					<label><span>frps 对外地址</span><input v-model="node.capabilities.runtime_settings.frp_advertise_addr" /></label>
					<label><span>frps 控制端口</span><input v-model.number="node.capabilities.runtime_settings.frp_bind_port" type="number" min="1" max="65535" /></label>
					<label><span>端口池起始</span><input v-model.number="node.capabilities.runtime_settings.port_range_start" type="number" min="1" max="65535" /></label>
					<label><span>端口池结束</span><input v-model.number="node.capabilities.runtime_settings.port_range_end" type="number" min="1" max="65535" /></label>
					<label class="toggle-row span-all"><input v-model="node.capabilities.runtime_settings.selectable" type="checkbox" /><span>允许客户端选择</span></label>
					<button class="ghost" type="button" :disabled="busy" @click="saveRemoteEdgeRuntime(node)">下发运行参数</button>
				  </template>
				  <div class="form-section span-all">修改 Edge 本地管理员</div>
				  <p class="span-all">密码仅在本次 HTTPS 请求和在线 mTLS 命令内存中短暂存在，不进入离线队列、MySQL 或审计详情。</p>
				  <label><span>管理员用户名</span><input v-model="edgeAdminForms[node.node_id].username" maxlength="64" /></label>
				  <label><span>显示名称</span><input v-model="edgeAdminForms[node.node_id].display_name" /></label>
				  <label><span>新密码</span><input v-model="edgeAdminForms[node.node_id].password" type="password" minlength="8" maxlength="72" autocomplete="new-password" /></label>
				  <label><span>确认新密码</span><input v-model="edgeAdminForms[node.node_id].password_confirm" type="password" minlength="8" maxlength="72" autocomplete="new-password" /></label>
				  <label class="span-all"><span>当前中心管理员密码（确认敏感操作）</span><input v-model="edgeAdminForms[node.node_id].controller_password" type="password" autocomplete="current-password" /></label>
				  <button class="primary" type="button" :disabled="busy || !node.connected || !edgeAdminForms[node.node_id].username || edgeAdminForms[node.node_id].password.length < 8" @click="rotateRemoteEdgeAdmin(node)">实时修改管理员凭据</button>
				</template>
			  </div>
			</div>
			<div class="result-box">
			  <h4>边缘节点 IP 控制</h4>
			  <p>单节点命令只作用于选中 Edge；全局规则会写入中心策略，并通过快照向离线后重连的 Edge 收敛。</p>
			  <form class="form-grid" @submit.prevent="updateEdgeIPBlock('block_ip')">
				<label><span>目标节点</span><select v-model="edgeBlockForm.node_id"><option v-for="node in edgeNodes" :key="node.node_id" :value="node.node_id">{{ node.name || node.node_id }}</option></select></label>
				<label><span>作用范围</span><select v-model="edgeBlockForm.scope"><option value="node">仅此节点</option><option value="global">全部节点</option></select></label>
				<label><span>IP 地址</span><input v-model="edgeBlockForm.ip" required placeholder="203.0.113.10" /></label>
				<label><span>原因</span><input v-model="edgeBlockForm.reason" placeholder="abuse" /></label>
				<div class="actions span-all"><button class="primary" type="submit" :disabled="busy || !edgeBlockForm.node_id">封禁</button><button class="ghost" type="button" :disabled="busy || !edgeBlockForm.node_id || !edgeBlockForm.ip" @click="updateEdgeIPBlock('unblock_ip')">解封</button></div>
			  </form>
			</div>
			<div class="result-box">
            <p>当前管理系统配置会写入运行目录下的 cfg 文件。frp 相关设置现在属于登录后的系统设置，不再出现在首次初始化流程里。</p>
            <code>{{ settingsForm.config_path || 'frp-control-server.cfg.json' }}</code>
			</div>
		  </template>
		  <div v-else class="result-box">
			<p><strong>{{ edgeStatusData?.node_name || '边缘节点' }}</strong></p>
			<p>节点 ID：<code>{{ edgeStatusData?.node_id || '-' }}</code></p>
			<p>中心：{{ edgeStatusData?.controller_address || '-' }}</p>
			<span class="pill" :class="edgeStatusData?.controller_connected ? 'active' : 'banned'">{{ edgeStatusData?.controller_connected ? '已连接' : '离线' }}</span>
			<p>EDGE 证书到期：{{ formatTime(edgeStatusData?.certificate_expires_at) }}</p>
			<div v-if="edgeStatusData?.certificate_expired" class="alert danger">EDGE 证书已到期。请在中心生成新的十分钟一次性注册凭证，然后在下方手动重新连接。</div>
			<p v-if="edgeStatusData?.certificate_error" class="danger-text">{{ edgeStatusData.certificate_error }}</p>
			<p v-if="edgeStatusData?.last_connection_error" class="danger-text">{{ edgeStatusData.last_connection_error }}</p>
			<div class="form-section">手动重新连接中心 / 更新一年证书</div>
			<form class="form-grid" @submit.prevent="reEnrollEdge">
			  <label class="span-all"><span>中心 HTTPS API 地址</span><input v-model="edgeReEnrollForm.controller_address" required placeholder="https://controller.example.com/api" /></label>
			  <label class="span-all"><span>节点名称</span><input v-model="edgeReEnrollForm.node_name" required /></label>
			  <label class="span-all"><span>新的十分钟一次性注册凭证</span><textarea v-model="edgeReEnrollForm.enrollment_token" required rows="5" /></label>
			  <button class="primary" type="submit" :disabled="busy || !edgeReEnrollForm.enrollment_token"><RefreshCw :size="16" />重新签发并写入 cfg</button>
			</form>
          </div>
        </section>
      </section>
    </section>
  </main>

  <div v-if="selectedUser" class="modal-backdrop" @click.self="closeUserDetail">
    <section class="detail-modal">
      <header class="detail-head">
        <div>
          <p class="eyebrow">User Detail</p>
          <h3>{{ selectedUser.username }}</h3>
        </div>
        <button class="icon-button" type="button" title="关闭" @click="closeUserDetail">
          <X :size="18" />
        </button>
      </header>

      <div class="detail-body">
        <section class="detail-section">
          <h4>用户信息</h4>
          <div class="detail-grid">
            <div><span>ID</span><strong>#{{ selectedUser.id }}</strong></div>
            <div><span>显示名</span><strong>{{ selectedUser.display_name || '-' }}</strong></div>
            <div><span>角色</span><strong>{{ selectedUser.role }}</strong></div>
            <div><span>状态</span><span class="pill" :class="selectedUser.status">{{ selectedUser.status }}</span></div>
            <div class="span-all" v-if="selectedUser.ban_reason"><span>封禁原因</span><strong>{{ selectedUser.ban_reason }}</strong></div>
          </div>
        </section>

        <section class="detail-section">
          <h4>用户控制</h4>
          <div class="control-row">
            <button v-if="selectedUser.status !== 'banned'" class="ghost danger-text" type="button" :disabled="busy" @click="setStatus('users', selectedUser.id, 'ban')">
              <Ban :size="16" />
              封禁用户
            </button>
            <button v-else class="ghost" type="button" :disabled="busy" @click="setStatus('users', selectedUser.id, 'unban')">
              <RotateCcw :size="16" />
              解封用户
            </button>
            <button class="ghost danger-text" type="button" :disabled="busy || me?.id === selectedUser.id" @click="deleteUser(selectedUser)">
              <Trash2 :size="16" />
              删除用户
            </button>
          </div>
        </section>

        <section class="detail-section">
          <h4>资源策略</h4>
          <form class="detail-form-grid" @submit.prevent="saveUserPolicy">
            <label><span>起始端口</span><input v-model.number="policyForm.port_start" type="number" min="1" /></label>
            <label><span>结束端口</span><input v-model.number="policyForm.port_end" type="number" min="1" /></label>
            <label><span>可开放数量</span><input v-model.number="policyForm.max_ports" type="number" min="1" /></label>
            <div class="protocol-checks span-all">
              <span>允许协议</span>
              <label v-for="protocol in protocolOptions" :key="protocol" class="protocol-check">
                <input v-model="policyForm.allowed_protocols" type="checkbox" :value="protocol" />
                <span>{{ protocol }}</span>
              </label>
            </div>
            <label class="toggle-row">
              <input v-model="policyForm.enabled" type="checkbox" />
              <span>启用策略</span>
            </label>
            <button class="primary" type="submit" :disabled="busy">
              <ShieldCheck :size="18" />
              保存策略
            </button>
          </form>
        </section>

        <section class="detail-section">
          <h4>DPI</h4>
          <div class="detail-form-grid">
            <label class="toggle-row">
              <input v-model="dpiForm.enabled" type="checkbox" />
              <span>Route this user through DPI gateway</span>
            </label>
            <button class="primary" type="button" :disabled="busy" @click="saveDpiGateway(selectedUser.id, dpiForm.enabled)">
              <ShieldCheck :size="18" />
              Save Gateway
            </button>
            <button class="ghost" type="button" @click="openDpiConfig(selectedUser)">
              <Settings :size="18" />
              Detail Config
            </button>
          </div>
        </section>

        <section class="detail-section">
          <h4>HTTPS API Token</h4>
          <div v-if="selectedUserTokens.length" class="token-detail-list">
            <div v-for="token in selectedUserTokens" :key="token.id" class="token-detail-row">
              <div class="token-row-head">
                <strong>{{ token.name }}</strong>
                <span class="pill" :class="token.status">{{ token.status }}</span>
              </div>
              <div class="token-copy-row">
                <input
                  class="token-input"
                  :value="token.plain_token || '旧 token 未保存明文，无法恢复完整值'"
                  readonly
                />
                <button class="icon-button" type="button" title="复制完整 token" :disabled="!token.plain_token" @click="copyText(token.plain_token || '')">
                  <Copy :size="16" />
                </button>
                <button v-if="!token.plain_token" class="icon-button" type="button" title="重新生成 token" :disabled="busy" @click="rotateToken(token)">
                  <RefreshCw :size="16" />
                </button>
              </div>
              <div class="control-row">
                <button v-if="token.status !== 'banned'" class="ghost danger-text" type="button" :disabled="busy" @click="setStatus('tokens', token.id, 'ban')">
                  <Ban :size="16" />
                  封禁凭证
                </button>
                <button v-else class="ghost" type="button" :disabled="busy" @click="setStatus('tokens', token.id, 'unban')">
                  <RotateCcw :size="16" />
                  解封凭证
                </button>
              </div>
              <div class="token-meta">
                <span>前缀：{{ token.token_prefix }}</span>
                <span>代理上限：{{ token.max_proxy_count }}</span>
                <span v-if="token.ban_reason">原因：{{ token.ban_reason }}</span>
              </div>
            </div>
          </div>
          <p v-else class="muted-text">这个用户还没有 API token。</p>
        </section>

        <section class="detail-section">
          <h4>客户端</h4>
          <div v-if="selectedUserClients.length" class="client-chip-list">
            <span v-for="client in selectedUserClients" :key="client.id" class="client-chip">
              {{ client.client_id }}
              <em>{{ client.status }}</em>
            </span>
          </div>
          <p v-else class="muted-text">暂时没有客户端连接记录。</p>
        </section>
      </div>
    </section>
  </div>

  <div v-if="showCreateUser" class="modal-backdrop" @click.self="closeCreateUser">
    <section class="detail-modal create-modal">
      <header class="detail-head">
        <div>
          <p class="eyebrow">New User</p>
          <h3>新建用户</h3>
        </div>
        <button class="icon-button" type="button" title="关闭" @click="closeCreateUser">
          <X :size="18" />
        </button>
      </header>
      <form class="create-user-form" @submit.prevent="createUser">
        <label><span>用户名</span><input v-model="userForm.username" required placeholder="testuser" /></label>
        <label><span>显示名</span><input v-model="userForm.display_name" placeholder="Test User" /></label>
        <label>
          <span>角色</span>
          <select v-model="userForm.role">
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
        </label>
        <label v-if="userForm.role === 'admin'"><span>密码</span><input v-model="userForm.password" required minlength="8" type="password" placeholder="至少 8 位" /></label>
        <p v-else class="muted-text">普通用户不登录后台，HTTPS API token 是唯一身份凭证。</p>
        <button class="primary" type="submit" :disabled="busy">
          <Plus :size="18" />
          创建用户
        </button>
      </form>
    </section>
  </div>

  <div v-if="toast" class="toast">{{ toast }}</div>
</template>
