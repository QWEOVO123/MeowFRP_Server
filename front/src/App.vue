<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
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
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import { panelPaths, panelSession, panelRedirect } from './router'
import type { AdvancedSettings, ConfigurationMode } from './types/advancedSettings'
import SettingsDialog from './components/SettingsDialog.vue'
import UserCacheSync from './components/UserCacheSync.vue'
import type { CacheNodeState } from './types/userCacheSync'
import { browserControlAPIURL } from './utils/setupDefaults'

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
    advanced_settings?: Omit<AdvancedSettings, 'mode' | 'http_addr' | 'config_path' | 'node' | 'controller' | 'edge'>
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
  { id: 'nodes', label: '多节点', icon: Server },
  { id: 'settings', label: '系统设置', icon: Settings },
  { id: 'dpi', label: 'DPI', icon: ShieldCheck },
  { id: 'advanced', label: '高级设置', icon: Settings },
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
const route = useRoute()
const pageRouter = useRouter()
const activeNav = computed<NavID>({
  get: () => route.meta.nav as NavID,
  set: nav => { void pageRouter.push(panelPaths[nav]) },
})
const isAdvancedPage = computed(() => Boolean(route.meta.advanced))
const pageTitle = computed(() => {
  if (!initialized.value) return '初始化'
  if (!databaseReady.value) return '数据库修复'
  if (!authed.value) return '登录'
  if (isAdvancedPage.value) return route.params.nodeID ? `${remoteAdvancedNode.value?.name || '边缘节点'} · 高级设置` : '高级设置'
  return visibleNavItems.value.find(item => item.id === activeNav.value)?.label || '页面不存在'
})
const selectedUserID = ref<number | null>(null)
const userNodeOptions = ref<{ node_id: string; name: string }[]>([])
const userNodeIDs = ref<string[]>([])
const userNodeAccessLoading = ref(false)
const userNodeAccessReady = ref(false)
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
const enrollmentExpiresAt = ref('')
const enrollmentError = ref('')
const edgeAccessEnabled = ref(false)
const edgeNodes = ref<EdgeNode[]>([])
const selectedNode = ref<EdgeNode | null>(null)
const nodeSearch = ref('')
const nodeDetailTab = ref<'directory' | 'permissions' | 'admin' | 'ip'>('directory')
const nodeDialog = ref<HTMLElement | null>(null)
const confirmNodeDeletion = ref(false)
const deleteNodeName = ref('')
let nodeTrigger: HTMLElement | null = null
let previousBodyOverflow = ''
const filteredNodes = computed(() => {
  const query = nodeSearch.value.trim().toLowerCase()
  return edgeNodes.value.filter(node => `${node.name} ${node.node_id} ${node.public_api_url}`.toLowerCase().includes(query))
})

async function openNodeDetail(node: EdgeNode) {
  nodeTrigger = document.activeElement as HTMLElement | null
  previousBodyOverflow = document.body.style.overflow
  selectedNode.value = JSON.parse(JSON.stringify(node)) as EdgeNode
  confirmNodeDeletion.value = false
  deleteNodeName.value = ''
  nodeDetailTab.value = 'directory'
  edgeBlockForm.node_id = node.node_id
  edgeBlockForm.scope = 'node'
  edgeBlockForm.ip = ''
  edgeBlockForm.reason = ''
  document.body.style.overflow = 'hidden'
  await nextTick()
  nodeDialog.value?.focus()
}

function closeNodeDetail() {
  if (busy.value) return
  const nodeID = selectedNode.value?.node_id
  if (nodeID && edgeAdminForms[nodeID]) {
    edgeAdminForms[nodeID].password = ''
    edgeAdminForms[nodeID].password_confirm = ''
    edgeAdminForms[nodeID].controller_password = ''
  }
  selectedNode.value = null
  document.body.style.overflow = previousBodyOverflow
  nodeTrigger?.focus()
  void refreshEdgeNodes()
}

async function deleteSelectedNode() {
  const node = selectedNode.value
  if (!node || busy.value || !confirmNodeDeletion.value || deleteNodeName.value !== (node.name || node.node_id)) return
  busy.value = true
  try {
    await api(`/api/v1/admin/nodes/${encodeURIComponent(node.node_id)}`, { method: 'DELETE' })
    busy.value = false
    closeNodeDetail()
    edgeClients.value = edgeClients.value.filter(client => client.node_id !== node.node_id)
    edgeConnections.value = edgeConnections.value.filter(connection => connection.node_id !== node.node_id)
    edgeTraffic.value = edgeTraffic.value.filter(traffic => traffic.node_id !== node.node_id)
    edgeRuntimeLogs.value = edgeRuntimeLogs.value.filter(log => log.node_id !== node.node_id)
    showToast('节点已删除。重新接入需使用新的接入 Token 注册，并重新分配节点权限。')
  } catch (error) { showError(error, '删除节点失败') }
  finally { busy.value = false }
}

function handleNodeDialogKey(event: KeyboardEvent) {
  if (event.key === 'Escape') { event.preventDefault(); closeNodeDetail(); return }
  if (event.key !== 'Tab') return
  const controls = Array.from(nodeDialog.value?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]') ?? []).filter(el => el.getClientRects().length)
  const first = controls[0]
  const last = controls[controls.length - 1]
  if (!first || !last) { event.preventDefault(); return }
  if (event.shiftKey && (document.activeElement === first || document.activeElement === nodeDialog.value)) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && (document.activeElement === last || document.activeElement === nodeDialog.value)) { event.preventDefault(); first.focus() }
}
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
  public_api_url: browserControlAPIURL(window.location.href),
  frp_advertise_addr: '127.0.0.1',
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
const setupAddressEdited = ref(false)
const setupIPDetecting = ref(false)
const setupIPMessage = ref('正在等待探测服务器公网 IPv4。')
const setupIPCandidates = ref<string[]>([])
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
  configuration_mode: 'manual' as ConfigurationMode,
  connection_tuning: { disable_tcp_mux: false, tcp_mux_keepalive_seconds: 0, tcp_keepalive_seconds: 0, max_pool_count: 0, heartbeat_timeout_seconds: 0, user_connection_timeout_seconds: 0, mtls_handshake_timeout_seconds: 0, disable_mtls_session_tickets: false, enable_mtls_session_resumption: false },
  embedded_frps_enabled: true,
  frp_bind_addr: '0.0.0.0',
  frp_proxy_bind_addr: '0.0.0.0',
  http_addr: '',
  frp_server_addr: '127.0.0.1',
  frp_server_port: 7000,
  frp_transport_tls: false,
  client_config_comment: 'generated by frp-control-server',
  session_ttl: '1h',
  runtime_token_ttl: '24h',
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
const frpsRuntime = ref<{ running: boolean; bind_addr?: string; bind_port?: number } | null>(null)
const advancedDraft = ref<typeof settingsForm | null>(null)
const remoteAdvancedNode = ref<{ node_id: string; name: string } | null>(null)
const advancedError = ref('')
const advancedSaving = ref(false)
const advancedLoading = ref(false)
const advancedSavedNotice = ref('')
const advancedBaseline = ref('')
let advancedLoadVersion = 0
const localNodeDraft = ref<typeof settingsForm | null>(null)
const nodeSettingsSaving = ref(false)
const nodeSettingsError = ref('')
const showEnrollment = ref(false)
const enrollmentForm = reactive({ expires_minutes: 10, node: { name: '', public_api_url: '', selectable: false } })
const localPermissionLabels = {
  reporting: { client_presence: '客户端在线状态', connections: '连接详情', traffic_statistics: '流量统计', dpi_events: 'DPI 事件', runtime_logs: '运行日志' },
  remote_commands: { disconnect_client: '踢出客户端', disconnect_connection: '断开连接', block_ip: '封禁 IP', change_runtime_settings: '修改运行参数' },
}
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
  ? navItems.filter((item) => item.id === 'overview' || item.id === 'settings' || item.id === 'nodes' || item.id === 'advanced')
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
    if (response.status === 401 && path !== '/api/v1/auth/login' && authed.value) authed.value = false
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
    if (!state.initialized) void loadSetupDefaults()
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

async function loadSetupDefaults() {
  if (setupIPDetecting.value) return
  setupIPDetecting.value = true
  setupIPMessage.value = '正在由服务端检测公网 IPv4，不会使用浏览器所在电脑的 IP。'
  try {
    const data = await api<{ frp_ipv4: { address: string; candidates: string[]; status: string; message: string } }>('/api/v1/system/setup-defaults')
    setupIPCandidates.value = data.frp_ipv4.candidates ?? []
    setupIPMessage.value = data.frp_ipv4.message
    if (!setupAddressEdited.value) setupForm.frp_advertise_addr = data.frp_ipv4.address
  } catch {
    setupIPMessage.value = '公网 IPv4 探测失败；保留当前填写值，请手动确认服务器的公网入站地址。'
  } finally { setupIPDetecting.value = false }
}

async function repairDatabase() {
  busy.value = true
  restartNotice.value = ''
  try {
    const data = await api<{ restart_required?: boolean }>('/api/v1/system/repair-database', {
      method: 'POST',
      body: JSON.stringify(repairForm),
    })
    databaseReady.value = true
    databaseRepairRequired.value = false
    if (data.restart_required) restartNotice.value = '数据库配置已更新，请重启后端以恢复 FRP 和多节点服务。'
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

async function refreshAll(requestReports = false) {
  lastError.value = ''
  if (requestReports) {
    try { await requestEdgeReports() } catch (error) { showError(error, '边缘数据拉取失败') }
  }
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
  await refreshEdgeNodes()
	await refreshEdgeClients(true)
	await refreshEdgeTelemetry(true)
}

let edgeReportRequest: Promise<void> | null = null
async function requestEdgeReports() {
  if (deploymentMode.value !== 'controller' || !edgeAccessEnabled.value) return
  if (!edgeReportRequest) edgeReportRequest = (async () => {
    const data = await api<{ results: Record<string, string> }>('/api/v1/admin/nodes/refresh', { method: 'POST' })
    const failures = Object.entries(data.results).filter(([, status]) => status !== 'updated')
    if (failures.length) showError(new Error(`部分节点数据拉取失败，失败节点保留上次快照：${failures.map(([id, status]) => `${id}: ${status}`).join('；')}`), '边缘数据部分拉取失败')
  })().finally(() => { edgeReportRequest = null })
  await edgeReportRequest
}

async function refreshEdgeNodes(quiet = true) {
  if (deploymentMode.value !== 'controller') {
    edgeNodes.value = []
    return
  }
  try {
    if (!quiet && edgeAccessEnabled.value) {
      await requestEdgeReports()
      await Promise.all([refreshEdgeClients(true), refreshEdgeTelemetry(true)])
    }
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
	if (!edgeNodes.value.some(node => node.node_id === edgeBlockForm.node_id)) edgeBlockForm.node_id = edgeNodes.value[0]?.node_id || ''
  } catch (error) { showError(error, '边缘节点列表加载失败') }
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
}

async function refreshEdgeClients(quiet = false) {
  try {
    if (!quiet) await requestEdgeReports()
    const data = await api<{ clients: EdgeClientPresence[] }>('/api/v1/admin/edge-clients')
    edgeClients.value = data.clients ?? []
  } catch (error) {
    if (!quiet) showError(error, '边缘客户端列表加载失败')
  }
}

async function refreshEdgeTelemetry(quiet = false) {
  try {
    if (!quiet) await requestEdgeReports()
    const [connectionData, trafficData, logData] = await Promise.all([
      api<{ connections: EdgeConnection[] }>('/api/v1/admin/edge-connections'),
      api<{ traffic: EdgeTraffic[] }>('/api/v1/admin/edge-traffic'),
      api<{ logs: EdgeRuntimeLog[] }>('/api/v1/admin/edge-runtime-logs?limit=100'),
    ])
    edgeConnections.value = connectionData.connections ?? []
    edgeTraffic.value = trafficData.traffic ?? []
    edgeRuntimeLogs.value = logData.logs ?? []
  } catch (error) {
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
    deploymentMode.value = 'controller'
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
  advancedDraft.value = null
  remoteAdvancedNode.value = null
  localNodeDraft.value = null
  showEnrollment.value = false
  enrollmentToken.value = ''
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
    openUserDetail(data.user)
    showToast('用户已创建，请在详情中分配允许访问的节点')
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
    cacheSyncRefreshVersion.value++
    const effect = !data.policy.enabled
      ? 'DPI 未启用，规则不会检测或拦截流量'
      : !data.policy.enabled_detectors?.length
        ? 'DPI 已启用但未选择检测器，不会检测或拦截流量'
      : data.policy.mode === 'monitor'
        ? 'DPI 已启用，仅监测、不阻断流量'
        : 'DPI 已启用，将按阻断规则处理流量'
    showToast(`策略已保存：${effect}。已安排主动推送，请查看节点确认状态`)
  } catch (error) {
    showError(error, 'DPI policy save failed')
  } finally {
    busy.value = false
  }
}

const cacheSyncRefreshVersion = ref(0)
async function fetchUserCacheStates(userID: number): Promise<CacheNodeState[]> {
  const data = await api<{ nodes: CacheNodeState[] }>(`/api/v1/admin/users/${userID}/cache-nodes`)
  return data.nodes || []
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
  if (!connection.inbound_ip || busy.value) return
  const reason = window.prompt(`全局拉黑入站 IP ${connection.inbound_ip}：中心及所有边缘节点均生效，离线节点上线后全量同步。请输入原因：`, `blocked from connection ${connection.id}`)
  if (reason === null) return
  busy.value = true
  try {
    await api('/api/v1/admin/blocked-ips', {
      method: 'POST',
      body: JSON.stringify({ ip: connection.inbound_ip, reason }),
    })
    await refreshConnections()
    showToast('入站 IP 已全局拉黑，已安排推送至所有边缘节点；离线节点上线后同步')
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
    showToast('入站 IP 已解除全局拉黑，已安排同步至所有边缘节点')
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
    const data = await api<{ settings: typeof settingsForm; frps?: { running: boolean; bind_addr?: string; bind_port?: number }; restart_required?: boolean }>('/api/v1/admin/system-settings')
	if (data.restart_required) restartNotice.value = '配置与当前监听状态尚未一致，请重启后端使 FRP / mTLS 参数生效。'
	frpsRuntime.value = data.frps ?? null
	const incoming = data.settings as any
    const { controller, node, edge, ...general } = incoming
    Object.assign(settingsForm, general)
    if (controller) Object.assign(settingsForm.controller, controller)
    if (node) Object.assign(settingsForm.node, node)
    if (edge) {
      const { reporting, remote_commands, ...edgeGeneral } = edge
      Object.assign(settingsForm.edge, edgeGeneral)
      if (reporting) Object.assign(settingsForm.edge.reporting, reporting)
      if (remote_commands) Object.assign(settingsForm.edge.remote_commands, remote_commands)
    }
    edgeAccessEnabled.value = deploymentMode.value === 'controller' && Boolean(controller?.edge_access_enabled)
    if (!edgeAccessEnabled.value) {
      enrollmentToken.value = ''
      enrollmentExpiresAt.value = ''
      enrollmentError.value = ''
      showEnrollment.value = false
    }
    return true
  } catch (error) {
    showError(error, '系统设置加载失败')
    return false
  }
}

function openAdvancedOptions() {
  if (busy.value || advancedSaving.value) return
  void pageRouter.push({ name: 'advanced' })
}

function advancedPayload(draft: AdvancedSettings) {
  return {
    configuration_mode: draft.configuration_mode,
    embedded_frps_enabled: draft.embedded_frps_enabled,
    frp_transport_tls: draft.frp_transport_tls,
    frp_bind_addr: draft.frp_bind_addr,
    frp_proxy_bind_addr: draft.frp_proxy_bind_addr,
    session_ttl: draft.session_ttl,
    runtime_token_ttl: draft.runtime_token_ttl,
    udp_connection_ttl: draft.udp_connection_ttl,
    client_config_comment: draft.client_config_comment,
    connection_tuning: draft.connection_tuning,
  }
}
const advancedDirty = computed(() => !!advancedDraft.value && JSON.stringify(advancedPayload(advancedDraft.value)) !== advancedBaseline.value)

async function loadAdvancedPage() {
  const version = ++advancedLoadVersion
  advancedLoading.value = true
  advancedError.value = ''
  advancedSavedNotice.value = ''
  advancedDraft.value = null
  remoteAdvancedNode.value = null
  try {
    const nodeID = route.params.nodeID
    if (typeof nodeID === 'string') {
      const data = await api<{ nodes: EdgeNode[] }>('/api/v1/admin/nodes')
      if (version !== advancedLoadVersion || !authed.value || !isAdvancedPage.value) return
      const node = (data.nodes ?? []).find(item => item.node_id === nodeID)
      if (!node) throw new Error('边缘节点不存在或已删除')
      if (!node.capabilities?.controller_administration_enabled || !node.capabilities?.remote_commands?.change_runtime_settings) throw new Error('边缘节点尚未授权中心管理和修改运行参数，请先在该边缘节点本地授权')
      if (!node.capabilities.advanced_settings) throw new Error('该边缘节点尚未上报高级参数，请更新边缘服务端并重新连接')
      remoteAdvancedNode.value = { node_id: node.node_id, name: node.name || node.node_id }
      advancedDraft.value = Object.assign(JSON.parse(JSON.stringify(settingsForm)), node.capabilities.advanced_settings, { mode: 'edge', http_addr: '', config_path: '' })
    } else {
      const latest = await api<{ settings: typeof settingsForm; frps?: { running: boolean } }>('/api/v1/admin/system-settings')
      if (version !== advancedLoadVersion || !authed.value || !isAdvancedPage.value) return
      advancedDraft.value = Object.assign(JSON.parse(JSON.stringify(settingsForm)), latest.settings)
      frpsRuntime.value = latest.frps ?? null
    }
    advancedBaseline.value = JSON.stringify(advancedPayload(advancedDraft.value!))
  } catch (error) {
    if (version === advancedLoadVersion) advancedError.value = error instanceof Error ? error.message : '高级设置加载失败'
  } finally { if (version === advancedLoadVersion) advancedLoading.value = false }
}

function openRemoteAdvancedOptions(node: EdgeNode) {
  if (busy.value || advancedSaving.value) return
  closeNodeDetail()
  void pageRouter.push({ name: 'edge-advanced', params: { nodeID: node.node_id } })
}

function closeAdvancedOptions() {
  if (advancedSaving.value) return
  void pageRouter.push(route.params.nodeID ? panelPaths.nodes : panelPaths.settings)
}

async function refreshPage() {
  if (advancedSaving.value || busy.value) return
  if (isAdvancedPage.value) {
    if (advancedDirty.value && !window.confirm('重新读取会丢弃未保存的高级参数，是否继续？')) return
    await loadAdvancedPage()
  } else await refreshAll()
}

function selectAdvancedMode(mode: ConfigurationMode) {
  const draft = advancedDraft.value
  if (!draft || advancedSaving.value) return
  draft.configuration_mode = mode
  if (mode === 'automatic') {
    draft.embedded_frps_enabled = true
    draft.frp_transport_tls = false
  }
}

async function saveAdvancedOptions() {
  const draft = advancedDraft.value
  if (!draft || advancedSaving.value) return
  advancedSaving.value = true
  advancedError.value = ''
  advancedSavedNotice.value = ''
  try {
    const payload = advancedPayload(draft)
    const remote = remoteAdvancedNode.value
    if (remote) {
      const data = await api<{ applied: boolean; delivered: boolean; result?: { restart_required?: boolean; advanced_settings?: EdgeNode['capabilities']['advanced_settings'] } }>(`/api/v1/admin/nodes/${encodeURIComponent(remote.node_id)}/advanced-settings`, { method: 'PUT', body: JSON.stringify(payload) })
      await refreshEdgeNodes()
      if (data.applied && data.result?.advanced_settings) Object.assign(draft, data.result.advanced_settings)
      advancedBaseline.value = JSON.stringify(advancedPayload(draft))
      advancedSavedNotice.value = data.applied ? (data.result?.restart_required ? '边缘高级参数已保存，请重启该边缘节点' : '边缘节点已应用高级参数') : data.delivered ? '已下发，等待边缘节点确认；当前页面是待应用参数' : '节点离线，高级参数已排队 10 分钟；当前页面是待应用参数'
      showToast(advancedSavedNotice.value)
      return
    }
    const data = await api<{ restart_required: boolean }>('/api/v1/admin/system-settings', { method: 'PUT', body: JSON.stringify(payload) })
    restartNotice.value = data.restart_required ? '高级选项已保存，请重启后端使 FRP / mTLS 监听与 TLS 参数生效。' : ''
    if (await loadSettings()) Object.assign(draft, JSON.parse(JSON.stringify(settingsForm)))
    advancedBaseline.value = JSON.stringify(advancedPayload(draft))
    advancedSavedNotice.value = data.restart_required ? '高级设置已保存，请重启本服务使监听与连接参数生效。' : '高级设置已保存。'
    showToast(data.restart_required ? '已保存，请重启后端' : '高级选项已保存')
  } catch (error) { advancedError.value = error instanceof Error ? error.message : '高级选项保存失败' }
  finally { advancedSaving.value = false }
}

async function saveRemoteEdgeRuntime(node: EdgeNode) {
  busy.value = true
  try {
    const data = await api<{ applied: boolean; delivered: boolean; result?: { restart_required?: boolean } }>(`/api/v1/admin/nodes/${encodeURIComponent(node.node_id)}/runtime-settings`, {
      method: 'PUT',
      body: JSON.stringify(node.capabilities.runtime_settings),
    })
    if (data.applied) {
      node.name = node.capabilities.runtime_settings.tag
      node.public_api_url = node.capabilities.runtime_settings.public_api_url
      node.selectable = node.capabilities.runtime_settings.selectable
      await refreshEdgeNodes()
    }
    showToast(data.applied ? (data.result?.restart_required ? '边缘节点已保存，请重启该节点使监听生效' : '边缘节点已应用设置') : data.delivered ? '已投递，等待边缘节点确认；目录暂不变更' : '节点离线，已排队 10 分钟；目录暂不变更')
  } catch (error) {
    showError(error, '修改 Edge 运行参数失败')
  } finally {
    busy.value = false
  }
}

async function persistClusterSettings(controller: typeof settingsForm.controller) {
  const data = await api<{ restart_required: boolean }>('/api/v1/admin/system-settings', { method: 'PUT', body: JSON.stringify({ controller }) })
  restartNotice.value = data.restart_required ? '多节点设置已保存，请重启后端使接入监听生效。' : ''
  await loadSettings()
  await refreshEdgeNodes()
  showToast(data.restart_required ? '已保存，请重启后端' : '多节点设置已保存')
}

async function toggleCluster(event: Event) {
  const target = event.target as HTMLInputElement
  const enabled = target.checked
  target.checked = edgeAccessEnabled.value
  if (nodeSettingsSaving.value) return
  nodeSettingsSaving.value = true
  try {
    // A toggle must not silently save unfinished edits from System Settings.
    const data = await api<{ settings: { controller: typeof settingsForm.controller } }>('/api/v1/admin/system-settings')
    const controller = data.settings.controller
    if (enabled && !controller.public_address) {
      activeNav.value = 'settings'
      showToast('请先在系统设置填写并保存中心对外接入地址')
      return
    }
    await persistClusterSettings({ ...controller, edge_access_enabled: enabled })
  }
  catch (error) { showError(error, '多节点开关保存失败') }
  finally { nodeSettingsSaving.value = false }
}

async function saveCenterSettings() {
  if (deploymentMode.value !== 'controller' || nodeSettingsSaving.value) return
  nodeSettingsSaving.value = true
  nodeSettingsError.value = ''
  try {
    const payload = { node: settingsForm.node, controller: { ...settingsForm.controller, edge_access_enabled: edgeAccessEnabled.value } }
    const data = await api<{ restart_required: boolean }>('/api/v1/admin/system-settings', { method: 'PUT', body: JSON.stringify(payload) })
    await loadSettings()
    restartNotice.value = data.restart_required ? '中心配置已保存，请重启中心服务使监听生效。' : ''
    showToast(data.restart_required ? '中心配置已保存，请重启中心服务' : '中心配置已保存')
  }
  catch (error) { nodeSettingsError.value = error instanceof Error ? error.message : '中心配置保存失败' }
  finally { nodeSettingsSaving.value = false }
}

function openLocalNodeSettings() {
  if (deploymentMode.value !== 'edge') return
  nodeSettingsError.value = ''
  localNodeDraft.value = JSON.parse(JSON.stringify(settingsForm))
}

async function saveLocalNodeSettings() {
  const draft = localNodeDraft.value
  if (!draft || nodeSettingsSaving.value) return
  nodeSettingsSaving.value = true
  nodeSettingsError.value = ''
  try {
    const payload = { node: draft.node, ...(deploymentMode.value === 'edge' ? { reporting: draft.edge.reporting, remote_commands: draft.edge.remote_commands, controller_administration_enabled: draft.edge.controller_administration_enabled } : {}) }
    const data = await api<{ restart_required: boolean }>('/api/v1/admin/system-settings', { method: 'PUT', body: JSON.stringify(payload) })
    restartNotice.value = data.restart_required ? '节点设置已保存，请重启后端使监听生效。' : ''
    await loadSettings()
    localNodeDraft.value = null
    showToast(data.restart_required ? '已保存，请重启后端' : '节点设置已保存')
  } catch (error) { nodeSettingsError.value = error instanceof Error ? error.message : '节点设置保存失败' }
  finally { nodeSettingsSaving.value = false }
}

function openEnrollment() {
  enrollmentError.value = ''
  enrollmentToken.value = ''
  enrollmentExpiresAt.value = ''
  Object.assign(enrollmentForm, { expires_minutes: 10, node: { name: '', public_api_url: '', selectable: false } })
  showEnrollment.value = true
}

function closeEnrollment() {
  if (busy.value) return
  showEnrollment.value = false
  enrollmentToken.value = ''
  enrollmentExpiresAt.value = ''
}

async function generateEnrollmentToken() {
  busy.value = true
  enrollmentError.value = ''
  try {
	const data = await api<{ enrollment_token: string; expires_at: string }>('/api/v1/admin/nodes/enrollment-tokens', { method: 'POST', body: JSON.stringify(enrollmentForm) })
	if (!data.enrollment_token) throw new Error('服务端未返回接入 Token，请确认已更新后端程序')
	enrollmentToken.value = data.enrollment_token
	enrollmentExpiresAt.value = data.expires_at
	showToast('一次性注册凭证已生成')
  } catch (error) {
    enrollmentError.value = error instanceof Error ? error.message : '生成接入 Token 失败'
    showError(error, '生成接入 Token 失败')
  } finally { busy.value = false }
}

async function saveRemoteEdgePermissions(node: EdgeNode) {
  busy.value = true
  try {
    const data = await api<{ applied: boolean; delivered: boolean }>(`/api/v1/admin/nodes/${encodeURIComponent(node.node_id)}/remote-permissions`, {
      method: 'PUT',
      body: JSON.stringify({ reporting: node.capabilities.reporting, remote_commands: node.capabilities.remote_commands }),
    })
    if (data.applied) await refreshEdgeNodes()
    showToast(data.applied ? '边缘节点已应用权限' : data.delivered ? '权限已投递，等待边缘节点确认' : '节点离线，权限已排队 10 分钟')
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
    showToast('边缘节点已确认执行踢出，客户端需要重新鉴权')
    await refreshEdgeClients(true)
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
    showToast('边缘节点已确认断开连接')
    await refreshEdgeTelemetry(true)
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
  void loadUserNodeAccess(user)
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

async function loadUserNodeAccess(user: User) {
  userNodeIDs.value = []
  userNodeOptions.value = []
  userNodeAccessReady.value = false
  if (user.role !== 'user') return
  userNodeAccessLoading.value = true
  try {
    const data = await api<{ node_ids: string[]; nodes: { node_id: string; name: string }[] }>(`/api/v1/admin/users/${user.id}/node-access`)
    if (selectedUserID.value !== user.id) return
    userNodeIDs.value = data.node_ids ?? []
    userNodeOptions.value = data.nodes ?? []
    userNodeAccessReady.value = true
  } catch (error) { showError(error, '节点权限加载失败') }
  finally { if (selectedUserID.value === user.id) userNodeAccessLoading.value = false }
}

async function saveUserNodeAccess() {
  if (!selectedUser.value || !userNodeAccessReady.value) return
  busy.value = true
  try {
    await api(`/api/v1/admin/users/${selectedUser.value.id}/node-access`, {
      method: 'PUT', body: JSON.stringify({ node_ids: userNodeIDs.value }),
    })
      showToast('节点权限已保存，边缘节点将在权限同步后生效')
  } catch (error) { showError(error, '保存登录权限失败') }
  finally { busy.value = false }
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
	    enabled_detectors: policy?.enabled_detectors != null
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
	if (activeNav.value === 'connections') void refreshConnections(true)
	connectedClientsTimer = window.setInterval(() => {
		if (authed.value && activeNav.value === 'clients') {
			void refreshConnectedClients(true)
		}
		if (authed.value && activeNav.value === 'connections') void refreshConnections(true)
	}, 3000)
}

function stopConnectedClientsRefresh() {
	if (connectedClientsTimer === null) return
	window.clearInterval(connectedClientsTimer)
	connectedClientsTimer = null
}

watch([authed, activeNav], ([isAuthed, nav]) => {
	if (isAuthed && nav === 'nodes') void refreshEdgeNodes()
	if (isAuthed && (nav === 'clients' || nav === 'connections')) {
		startConnectedClientsRefresh()
		return
	}
	stopConnectedClientsRefresh()
})

watch([loading, initialized, databaseReady, authed, deploymentMode, backendMessage], () => {
  Object.assign(panelSession, {
    ready: !loading.value && !backendMessage.value, initialized: initialized.value,
    databaseReady: databaseReady.value, authed: authed.value, edge: deploymentMode.value === 'edge',
  })
  const redirect = panelRedirect(route)
  if (redirect) void pageRouter.replace(redirect)
}, { immediate: true })

watch(pageTitle, title => { document.title = `${title} · MeowFRP` }, { immediate: true })

watch([loading, authed, () => route.name, () => route.params.nodeID], () => {
  if (!loading.value && authed.value && isAdvancedPage.value) void loadAdvancedPage()
  else {
    advancedLoadVersion++
    advancedDraft.value = null
    remoteAdvancedNode.value = null
    advancedSavedNotice.value = ''
  }
}, { immediate: true })

const removeLeaveGuard = pageRouter.beforeEach((to, from) => {
  if (!authed.value) return true
  if (to.name === from.name && to.params.nodeID === from.params.nodeID) return true
  if (from.meta.advanced && advancedSaving.value) return false
  if (from.meta.advanced && advancedDirty.value && !window.confirm('高级设置有未保存的修改，是否放弃并离开？')) return false
  return true
})

watch(() => route.path, () => {
  if (selectedNode.value) closeNodeDetail()
  selectedUserID.value = null
  showCreateUser.value = false
  localNodeDraft.value = null
  showEnrollment.value = false
  lastError.value = ''
})

function protectAdvancedUnload(event: BeforeUnloadEvent) {
  if (!authed.value || !isAdvancedPage.value || (!advancedDirty.value && !advancedSaving.value)) return
  event.preventDefault()
  event.returnValue = ''
}

onMounted(initialize)
onMounted(() => window.addEventListener('beforeunload', protectAdvancedUnload))
onUnmounted(() => {
  stopConnectedClientsRefresh()
  removeLeaveGuard()
  window.removeEventListener('beforeunload', protectAdvancedUnload)
})
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
        <div class="form-section span-all">中心访问地址</div>
        <label class="span-all"><span>控制 API URL / 中心管理地址</span><input v-model="setupForm.public_api_url" type="url" required placeholder="https://relay.qweovo.top/api" /><small>默认使用当前浏览器域名并追加 /api，可手动修改反向代理路径或端口；填写客户端能够访问的 HTTPS 地址。若当前网站使用 HTTP，请先确认宝塔/反代已配置 HTTPS；本地回环调试可用 HTTP。</small></label>
        <label class="span-all"><span>FRP 下发地址（服务器公网 IPv4）</span><input v-model="setupForm.frp_advertise_addr" required placeholder="127.0.0.1" @input="setupAddressEdited = true" /><small>仅检测到唯一地址时自动填入；多地址或结果不确定时保留 127.0.0.1。手动填写不会被后续探测覆盖。</small></label>
        <div class="setup-ip-status span-all"><p role="status">{{ setupIPMessage }}</p><p v-if="setupIPCandidates.length">检测到的候选：<code>{{ setupIPCandidates.join('、') }}</code></p><p v-if="setupAddressEdited">已使用手动填写值，重新探测只更新提示，不覆盖输入。</p><button class="ghost" type="button" :disabled="busy || setupIPDetecting" @click="loadSetupDefaults"><RefreshCw :size="16" />{{ setupIPDetecting ? '检测中…' : '重新检测公网 IPv4' }}</button></div>
        <p v-if="setupForm.frp_advertise_addr === '127.0.0.1'" class="alert warning span-all">FRP 下发地址仍为 127.0.0.1，远程客户端不能用它连接本服务器。可先初始化，但上线前请在系统设置中填写正确的中心公网地址。</p>
        <div class="form-section span-all">管理员</div>
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
        <button class="primary" type="submit" :disabled="busy || setupIPDetecting">
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
        <RouterLink
		  v-for="item in visibleNavItems"
          :key="item.id"
          :to="panelPaths[item.id]"
          :class="{ active: activeNav === item.id }"
        >
          <component :is="item.icon" :size="18" />
          {{ item.label }}
        </RouterLink>
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
		  <h2>{{ pageTitle }}</h2>
        </div>
        <button class="ghost" type="button" :disabled="advancedSaving || advancedLoading || busy" @click="refreshPage">
          <RefreshCw :size="18" />
          刷新
        </button>
      </header>
      <div v-if="lastError" class="alert danger page-alert">{{ lastError }}</div>

      <RouterView v-slot="{ Component }">
        <template v-if="isAdvancedPage">
          <section v-if="advancedLoading" class="panel route-status" aria-live="polite"><RefreshCw :size="24" /><h3>正在读取{{ route.params.nodeID ? '边缘节点' : '本服务' }}高级参数…</h3></section>
          <component v-else-if="advancedDraft" :is="Component" :settings="advancedDraft" :busy="advancedSaving" :error="advancedError" :notice="advancedSavedNotice" :dirty="advancedDirty" :node-label="remoteAdvancedNode?.name" :remote="!!remoteAdvancedNode" :frps-running="remoteAdvancedNode ? null : frpsRuntime?.running ?? null" @close="closeAdvancedOptions" @mode="selectAdvancedMode" @save="saveAdvancedOptions" @reload="refreshPage" />
          <section v-else class="panel route-status"><h3>无法读取高级参数</h3><p class="danger-text" role="alert">{{ advancedError || '请重新读取配置' }}</p><div class="actions"><button class="primary" type="button" @click="loadAdvancedPage">重试</button><button class="ghost" type="button" @click="closeAdvancedOptions">返回</button></div></section>
        </template>
        <component v-else :is="Component">
          <section v-if="route.name === 'not-found'" class="panel route-status"><h3>404 · 页面不存在</h3><p>请检查地址，或从左侧导航打开管理栏目。</p><RouterLink class="primary" :to="panelPaths.overview">返回总览</RouterLink></section>
      <section v-if="activeNav === 'overview'" class="page-stack">
        <section class="panel advanced-entry">
          <div><p class="eyebrow">配置控制台</p><h3>正常使用交给默认配置，需要时再精细调整</h3><p>{{ settingsForm.configuration_mode === 'automatic' ? '自动配置 · 内置 FRP 开启，FRP TLS 关闭' : '手动配置 · 保留已有参数' }}，其他参数和访问权限保持不变。</p></div>
          <button class="primary" type="button" :disabled="busy" @click="openAdvancedOptions"><Settings :size="18" />高级选项</button>
        </section>
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
              <p>显示上次请求的快照（离线节点可能保留旧数据）。点击“拉取数据”主动请求边缘上报；踢出命令即时下发。</p>
            </div>
            <button class="ghost" type="button" @click="refreshEdgeClients()"><RefreshCw :size="16" />拉取数据</button>
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
                <tr v-if="!edgeClients.length"><td colspan="7" class="muted-text">暂无客户端快照。请点击“拉取数据”，并确认边缘节点已开启客户端状态上报。</td></tr>
              </tbody>
            </table>
          </div>
        </section>
      </section>

      <section v-if="activeNav === 'clientHistory'" class="page-stack">
        <section class="panel">
          <div class="panel-head">
            <h3>历史客户端</h3>
            <button class="ghost" type="button" @click="refreshAll(true)">
              <RefreshCw :size="16" />
              拉取数据
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
                      title="全局拉黑入站 IP（中心及所有边缘节点）"
                      aria-label="全局拉黑入站 IP"
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
              <p>心跳仅保活；点击“拉取数据”获取连接快照。拉黑入站 IP 为全局操作，主动同步至所有边缘节点；节点上线或重连后全量同步黑名单。</p>
            </div>
            <button class="ghost" type="button" @click="refreshEdgeTelemetry()"><RefreshCw :size="18" />拉取数据</button>
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
                  <td class="actions">
                    <button v-if="connection.can_terminate" class="icon-button danger" type="button" title="通过 EDGE 断开 TCP 连接" :disabled="busy" @click="disconnectEdgeConnection(connection)"><X :size="16" /></button>
                    <button class="icon-button danger" type="button" title="全局拉黑入站 IP（中心及所有边缘节点）" aria-label="全局拉黑入站 IP" :disabled="busy || !connection.inbound_ip" @click="blockConnectionIP(connection)"><Ban :size="16" /></button>
                  </td>
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
            <div><h3>全局入站 IP 黑名单</h3><p>中心与所有边缘节点统一执行。新增、修改和解封主动增量同步；边缘节点上线或重连后完整同步。节点本地单独设置的封禁规则不受全局解封影响。</p></div>
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
            <button class="ghost" type="button" @click="refreshAll(true)">
              <RefreshCw :size="18" />
              拉取数据
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
            <h3>DPI 用户策略</h3>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>DPI 状态</th>
                  <th>Mode</th>
                  <th>HTTP</th>
                  <th>TLS</th>
                  <th>QUIC</th>
                  <th>SS</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="user in safeUsers" :key="user.id">
                  <td>{{ user.username }}</td>
                  <td><span class="pill" :class="{ active: dpiPolicyForUser(user.id)?.enabled }">{{ dpiPolicyForUser(user.id)?.enabled ? '已启用' : '未启用' }}</span></td>
                  <td><span class="pill active">{{ dpiPolicyForUser(user.id)?.mode || 'monitor' }}</span></td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_http ?? true ? 'allow' : 'block' }}</td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_tls ?? true ? 'allow' : 'block' }}</td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_quic ?? true ? 'allow' : 'block' }}</td>
                  <td>{{ dpiPolicyForUser(user.id)?.allow_encrypted_tunnel ?? true ? 'allow' : 'block' }}</td>
                  <td><button class="ghost" type="button" :disabled="busy" @click="loadDpiForm(user.id)">配置策略</button></td>
                </tr>
                <tr v-if="!safeUsers.length"><td colspan="8" class="muted-text">暂无用户，请先在用户管理中创建用户。</td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <section v-if="dpiForm.user_id" class="panel">
          <div class="panel-head">
            <h3>DPI 策略配置 - {{ userName(dpiForm.user_id) }}</h3>
          </div>
          <form class="form-grid dpi-config-grid" @submit.prevent="saveDpiPolicy()">
            <label class="toggle-row span-all">
              <input v-model="dpiForm.enabled" type="checkbox" role="switch" :disabled="busy" />
              <span>启用此用户的 DPI 策略（保存后生效）</span>
            </label>
            <p v-if="!dpiForm.enabled" class="alert warning span-all" role="status">DPI 当前未启用。保存仅保存并同步配置，不会检测或拦截流量；节点显示“已同步”不代表 DPI 已启用。</p>
            <p v-else-if="dpiForm.mode === 'monitor'" class="alert warning span-all" role="status">当前为仅监测模式，不会阻断流量。如需拦截，请选择“阻断不允许的流量”并保存。</p>
            <p v-else class="muted-text span-all" role="status">保存后将启用 DPI 阻断规则；边缘节点须确认同步后才会应用新配置。</p>
            <label>
              <span>检测模式</span>
              <select v-model="dpiForm.mode">
                <option value="monitor">仅监测，不阻断</option>
                <option value="block">阻断不允许的流量</option>
              </select>
            </label>
            <label>
              <span>Max inspect bytes</span>
              <input v-model.number="dpiForm.max_inspect_bytes" type="number" min="512" max="65536" />
            </label>
            <div class="protocol-checks span-all">
              <span>Detectors</span>
              <label v-for="detector in dpiDetectorOptions" :key="detector.id" class="protocol-check">
                <input v-model="dpiForm.enabled_detectors" type="checkbox" role="switch" :value="detector.id" />
                <span>{{ detector.label }}</span>
              </label>
            </div>
            <p v-if="!dpiForm.enabled_detectors.length" class="alert warning span-all" role="status">未选择检测器：保存后不会执行任何协议检测或拦截。重新勾选检测器并保存才能恢复检测。</p>
            <div class="protocol-checks span-all">
              <span>允许的流量类型：关闭后，阻断模式下命中该类型将被拦截。</span>
              <label class="protocol-check"><input v-model="dpiForm.allow_http" type="checkbox" role="switch" /><span>HTTP</span></label>
              <label class="protocol-check"><input v-model="dpiForm.allow_tls" type="checkbox" role="switch" /><span>TLS</span></label>
              <label class="protocol-check"><input v-model="dpiForm.allow_quic" type="checkbox" role="switch" /><span>QUIC</span></label>
              <label class="protocol-check"><input v-model="dpiForm.allow_encrypted_tunnel" type="checkbox" role="switch" /><span>SS / encrypted tunnel</span></label>
            </div>
            <button class="primary" type="submit" :disabled="busy">
              <ShieldCheck :size="18" />
              保存 DPI 策略
            </button>
          </form>
          <UserCacheSync v-if="deploymentMode === 'controller'" :user-id="dpiForm.user_id" :refresh-version="cacheSyncRefreshVersion" :fetch-states="fetchUserCacheStates" />
        </section>

        <section class="panel">
          <div class="panel-head">
            <h3>DPI Hit Details</h3>
            <button class="ghost" type="button" @click="refreshAll(true)">
              <RefreshCw :size="18" />
              拉取数据
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

      <section v-if="activeNav === 'settings' || activeNav === 'nodes'" class="page-stack">
        <section v-if="activeNav === 'nodes' && deploymentMode === 'controller'" class="panel cluster-control">
          <div><h3>多节点</h3><label class="toggle-row"><input :checked="edgeAccessEnabled" type="checkbox" role="switch" :disabled="busy || nodeSettingsSaving" @change="toggleCluster" /><span>启用多节点接入</span></label><p>{{ edgeAccessEnabled ? '已允许边缘节点注册和连接。' : '多节点已关闭，现有节点记录与配置仍保留。' }}</p></div>
          <div class="actions"><button class="ghost" type="button" @click="activeNav = 'settings'"><Settings :size="16" />中心系统设置</button><button v-if="edgeAccessEnabled" class="primary" type="button" :disabled="busy || nodeSettingsSaving" @click="openEnrollment"><Plus :size="17" />新增接入</button></div>
        </section>
        <section v-if="activeNav === 'settings'" class="panel side-panel">
          <div class="panel-head">
			<h3>{{ deploymentMode === 'edge' ? '系统设置' : '中心节点设置' }}</h3>
            <button class="ghost" type="button" :disabled="busy" @click="openAdvancedOptions"><Settings :size="17" />高级选项</button>
          </div>
          <form v-if="deploymentMode === 'controller'" class="controller-settings" @submit.prevent="saveCenterSettings">
            <p v-if="nodeSettingsError" class="alert danger" role="alert">{{ nodeSettingsError }}</p>
            <section class="settings-block" aria-labelledby="auth-settings-title">
              <header class="settings-block-head"><span class="settings-block-icon"><KeyRound :size="21" /></span><div><h4 id="auth-settings-title">鉴权配置</h4><p>控制 API 入口、管理员会话与用户登录方式。</p></div></header>
              <div class="settings-fields">
                <label class="span-all"><span>中心控制 API URL</span><input v-model="settingsForm.node.public_api_url" required placeholder="https://center.example.com/api" :disabled="nodeSettingsSaving" /><small>客户端先在此鉴权，再获取允许访问的节点列表。</small></label>
                <div class="settings-info"><span>用户鉴权</span><strong>唯一 Token 鉴权</strong><p>普通用户的 Token 在创建时自动生成。中心验证后仅返回已授权节点。</p><button class="ghost" type="button" @click="activeNav = 'users'"><Users :size="16" />管理用户与节点权限</button></div>
              </div>
            </section>
            <section class="settings-block" aria-labelledby="frp-settings-title">
              <header class="settings-block-head"><span class="settings-block-icon"><Cable :size="21" /></span><div><h4 id="frp-settings-title">FRP 配置</h4><p>中心节点的对外地址、端口池和隧道传输配置。</p></div></header>
              <div class="settings-fields">
                <p v-if="frpsRuntime" class="settings-note span-all">当前进程 FRP：{{ frpsRuntime.running ? '运行中' : '未运行' }}。启停与监听设置保存后需重启后端；防火墙放行不代表服务已启动。</p>
                <label><span>中心节点名称</span><input v-model="settingsForm.node.tag" required maxlength="128" :disabled="nodeSettingsSaving" /></label>
                <label><span>中心 frps 对外地址</span><input v-model="settingsForm.node.frp_advertise_addr" required :disabled="nodeSettingsSaving" /></label>
                <label><span>中心 frps 控制端口</span><input v-model.number="settingsForm.node.frp_bind_port" type="number" min="1" max="65535" required :disabled="nodeSettingsSaving" /></label>
                <label><span>可用端口起始</span><input v-model.number="settingsForm.node.port_range_start" type="number" min="1" max="65535" required :disabled="nodeSettingsSaving" /></label>
                <label><span>可用端口结束</span><input v-model.number="settingsForm.node.port_range_end" type="number" :min="settingsForm.node.port_range_start" max="65535" required :disabled="nodeSettingsSaving" /></label>
                <label class="toggle-row span-all"><input v-model="settingsForm.node.selectable" type="checkbox" role="switch" :disabled="nodeSettingsSaving" /><span>允许获授权用户选择中心节点</span></label>
                <p class="settings-note span-all">用户实际可用端口取用户策略与节点端口池的交集。访问中心节点同样需要用户节点授权。</p>
              </div>
            </section>
            <section class="settings-block" aria-labelledby="channel-settings-title">
              <header class="settings-block-head"><span class="settings-block-icon"><Server :size="21" /></span><div><h4 id="channel-settings-title">中心管理通道</h4><p>中心自身的 mTLS 监听与接入地址；边缘节点配置在各节点设置中下发。</p></div></header>
              <div class="settings-fields">
                <label><span>中心 mTLS 监听地址</span><input v-model="settingsForm.controller.listen_addr" required placeholder="0.0.0.0:9443" :disabled="nodeSettingsSaving" /></label>
                <label><span>中心对外接入地址</span><input v-model="settingsForm.controller.public_address" :required="edgeAccessEnabled" placeholder="center.example.com:9443" :disabled="nodeSettingsSaving" /></label>
                <label><span>节点心跳间隔（秒）</span><input v-model.number="settingsForm.controller.heartbeat_interval_seconds" type="number" min="2" max="60" required :disabled="nodeSettingsSaving" /></label>
                <p class="settings-note span-all">多节点开关与新增接入 Token 位于“多节点”。现有 CA 和证书保留；监听地址修改后需要重启中心服务。</p>
              </div>
            </section>
            <footer class="settings-save-bar"><p>只保存中心配置，不修改任何边缘节点。</p><button class="primary" type="submit" :disabled="busy || nodeSettingsSaving">{{ nodeSettingsSaving ? '保存中…' : '保存中心配置' }}</button></footer>
          </form>
          <div v-else class="result-box"><h4>本节点配置已集中管理</h4><p>地址、端口池、上报、远程管理权限及重新连接中心均在多节点选项卡管理。</p><button class="ghost" type="button" @click="activeNav = 'nodes'"><Server :size="16" />打开多节点</button></div>
        </section>
        <section v-if="activeNav === 'nodes'" class="panel">
          <div class="panel-head">
			<h3>{{ deploymentMode === 'controller' ? '边缘节点列表' : '本边缘节点' }}</h3>
			<button v-if="activeNav === 'nodes'" class="ghost" type="button" :disabled="busy" @click="refreshEdgeNodes(false)"><RefreshCw :size="16" />拉取数据</button>
          </div>
		  <template v-if="deploymentMode === 'controller'">
			<div class="result-box">
			  <p>仅管理边缘节点，通过 mTLS 通道下发地址、权限、端口池和 IP 控制；中心自身配置请进入系统设置。</p>
              <div class="node-toolbar">
                <label class="node-search"><span>搜索节点</span><input v-model="nodeSearch" placeholder="名称、节点 ID 或 API 地址" /></label>
                <span class="muted-text">{{ filteredNodes.length }} 个边缘节点</span>
              </div>
              <div class="table-wrap">
                <table class="node-table">
                  <thead><tr><th>节点</th><th>连接状态</th><th>公开 API</th><th>客户端可选</th><th>操作</th></tr></thead>
                  <tbody>
                    <tr v-for="node in filteredNodes" :key="node.node_id">
                      <td><div class="node-identity"><span class="node-avatar"><Server :size="19" /></span><div><strong>{{ node.name || '未命名节点' }}</strong><small>{{ node.node_id }}</small></div></div></td>
                      <td><span class="pill" :class="node.connected ? 'active' : 'offline'">{{ node.connected ? '在线' : '离线' }}</span></td>
                      <td><span class="node-endpoint" :title="node.public_api_url">{{ node.public_api_url || '尚未配置' }}</span></td>
                      <td>{{ node.selectable ? '已开放' : '未开放' }}</td>
                      <td><button class="ghost" type="button" @click="openNodeDetail(node)"><Settings :size="16" />设置</button></td>
                    </tr>
                    <tr v-if="!filteredNodes.length"><td colspan="5" class="muted-text">{{ edgeNodes.length ? '没有找到匹配的边缘节点。' : '暂无已接入的边缘节点。' }}</td></tr>
                  </tbody>
                </table>
              </div>
			</div>
		  </template>
		  <div v-else class="result-box">
            <div class="node-toolbar"><div><h4>{{ settingsForm.node.tag || '边缘节点' }}</h4><p>本节点的地址、端口池、信息上报与中心授权</p></div><button class="ghost" type="button" :disabled="busy || nodeSettingsSaving" @click="openLocalNodeSettings"><Settings :size="16" />设置</button></div>
			<p><strong>{{ edgeStatusData?.node_name || '边缘节点' }}</strong></p>
			<p>节点 ID：<code>{{ edgeStatusData?.node_id || '-' }}</code></p>
			<p>中心：{{ edgeStatusData?.controller_address || '-' }}</p>
			<span class="pill" :class="edgeStatusData?.controller_connected ? 'active' : 'banned'">{{ edgeStatusData?.controller_connected ? '已连接' : '离线' }}</span>
			<p>EDGE 证书到期：{{ formatTime(edgeStatusData?.certificate_expires_at) }}</p>
			<div v-if="edgeStatusData?.certificate_expired" class="alert danger">EDGE 证书已到期。请在中心“多节点 → 新增接入”生成一次性 Token，然后进入本节点设置重新连接。</div>
			<p v-if="edgeStatusData?.certificate_error" class="danger-text">{{ edgeStatusData.certificate_error }}</p>
			<p v-if="edgeStatusData?.last_connection_error" class="danger-text">{{ edgeStatusData.last_connection_error }}</p>
            <p>重新连接中心或更新证书，请点击本节点的“设置”按钮。</p>
          </div>
        </section>
      </section>
        </component>
      </RouterView>
    </section>
  </main>

  <Transition name="glass-modal" :duration="300">
    <SettingsDialog v-if="showEnrollment && authed" title="新增节点接入" :busy="busy" @close="closeEnrollment">
      <form class="form-grid" @submit.prevent="generateEnrollmentToken">
        <p class="settings-note span-all">设置新节点的初始目录信息，生成一次性 Token，再到边缘节点初始化页面完成注册。节点注册成功后会出现在列表中。</p>
        <fieldset class="form-grid span-all enrollment-fields" :disabled="busy || !!enrollmentToken">
          <label><span>新节点名称（可选）</span><input v-model="enrollmentForm.node.name" maxlength="128" placeholder="留空沿用边缘节点注册名称" /></label>
          <label><span>Token 有效期（分钟）</span><input v-model.number="enrollmentForm.expires_minutes" type="number" min="1" max="60" required /></label>
          <label class="span-all"><span>新节点公开 API URL</span><input v-model="enrollmentForm.node.public_api_url" :required="enrollmentForm.node.selectable" placeholder="https://edge.example.com/api" /></label>
          <label class="toggle-row span-all"><input v-model="enrollmentForm.node.selectable" type="checkbox" role="switch" /><span>注册后允许客户端选择（仍需用户节点授权）</span></label>
        </fieldset>
        <div class="advanced-file-info span-all"><p>中心 HTTPS API：<code>{{ settingsForm.node.public_api_url }}</code></p><p>节点接入地址：<code>{{ settingsForm.controller.public_address }}</code></p><p>目录设置绑定本 Token，使用时写入中心节点列表；边缘服务器自己的监听地址和端口池仍需在该节点设置中配置。</p></div>
        <p v-if="restartNotice" class="alert span-all">{{ restartNotice }}</p>
        <p v-if="enrollmentError" class="alert danger span-all" role="alert">{{ enrollmentError }}</p>
        <template v-if="enrollmentToken">
          <label class="span-all"><span>一次性接入 Token</span><textarea :value="enrollmentToken" aria-label="边缘节点接入 Token" rows="4" readonly /></label>
          <p class="settings-note span-all">有效期至 {{ formatTime(enrollmentExpiresAt) }}，仅可使用一次。关闭窗口后不再显示，请先复制保存。</p>
          <div class="actions span-all"><button class="primary" type="button" @click="copyText(enrollmentToken)"><Copy :size="16" />复制 Token</button><button class="ghost" type="button" @click="closeEnrollment">完成</button></div>
        </template>
        <div v-else class="actions span-all"><button class="ghost" type="button" :disabled="busy" @click="closeEnrollment">取消</button><button class="primary" type="submit" :disabled="busy || !edgeAccessEnabled"><KeyRound :size="16" />{{ busy ? '生成中…' : '生成接入 Token' }}</button></div>
      </form>
    </SettingsDialog>
  </Transition>

  <Transition name="glass-modal" :duration="300">
    <SettingsDialog v-if="localNodeDraft && authed" :title="`${localNodeDraft.node.tag || '本节点'} · 设置`" :busy="nodeSettingsSaving || busy" @close="localNodeDraft = null">
      <form class="form-grid" @submit.prevent="saveLocalNodeSettings">
        <p v-if="nodeSettingsError" class="alert danger span-all" role="alert">{{ nodeSettingsError }}</p>
        <fieldset class="form-grid span-all enrollment-fields" :disabled="nodeSettingsSaving || busy">
          <label><span>节点名称</span><input v-model="localNodeDraft.node.tag" required /></label>
          <label><span>公开 API URL</span><input v-model="localNodeDraft.node.public_api_url" required placeholder="https://node.example.com/api" /></label>
          <label><span>FRP 对外地址</span><input v-model="localNodeDraft.node.frp_advertise_addr" required /></label>
          <label><span>FRP 控制端口</span><input v-model.number="localNodeDraft.node.frp_bind_port" type="number" min="1" max="65535" required /></label>
          <label><span>端口池起始</span><input v-model.number="localNodeDraft.node.port_range_start" type="number" min="1" max="65535" required /></label>
          <label><span>端口池结束</span><input v-model.number="localNodeDraft.node.port_range_end" type="number" min="1" max="65535" required /></label>
          <label class="toggle-row span-all"><input v-model="localNodeDraft.node.selectable" type="checkbox" role="switch" /><span>允许客户端选择本节点（仍需用户节点授权）</span></label>
          <template v-if="deploymentMode === 'edge'">
            <label class="toggle-row span-all"><input v-model="localNodeDraft.edge.controller_administration_enabled" type="checkbox" role="switch" /><span>允许中心远程管理本节点</span></label>
            <div class="form-section span-all">信息上报</div>
            <label v-for="(label, key) in localPermissionLabels.reporting" :key="key" class="toggle-row"><input v-model="localNodeDraft.edge.reporting[key]" type="checkbox" role="switch" /><span>{{ label }}</span></label>
            <div class="form-section span-all">接受中心命令</div>
            <label v-for="(label, key) in localPermissionLabels.remote_commands" :key="key" class="toggle-row"><input v-model="localNodeDraft.edge.remote_commands[key]" type="checkbox" role="switch" /><span>{{ label }}</span></label>
          </template>
        </fieldset>
        <p class="settings-note span-all">仅保存本节点参数，不更改其他节点；FRP 控制端口变更需要重启。内置 FRP 默认开启，TLS 默认关闭；高级传输调优使用主页高级选项。</p>
        <div class="actions span-all"><button class="ghost" type="button" :disabled="nodeSettingsSaving || busy" @click="localNodeDraft = null">取消</button><button class="primary" type="submit" :disabled="nodeSettingsSaving || busy">{{ nodeSettingsSaving ? '保存中…' : '保存节点设置' }}</button></div>
      </form>
      <details v-if="deploymentMode === 'edge'" class="advanced-section reconnect-section"><summary>重新连接中心 / 更新节点证书</summary><form class="form-grid" @submit.prevent="reEnrollEdge"><label class="span-all"><span>中心 HTTPS API 地址</span><input v-model="edgeReEnrollForm.controller_address" required /></label><label class="span-all"><span>节点名称</span><input v-model="edgeReEnrollForm.node_name" required /></label><label class="span-all"><span>新的接入 Token</span><textarea v-model="edgeReEnrollForm.enrollment_token" required rows="4" /></label><button class="primary" type="submit" :disabled="busy || nodeSettingsSaving || !edgeReEnrollForm.enrollment_token">重新签发证书并写入 cfg</button></form></details>
    </SettingsDialog>
  </Transition>

  <Transition name="glass-modal" :duration="300">
  <div v-if="selectedNode" class="modal-backdrop" @click.self="closeNodeDetail">
    <section ref="nodeDialog" class="detail-modal node-modal" role="dialog" aria-modal="true" aria-labelledby="node-dialog-title" tabindex="-1" @keydown="handleNodeDialogKey">
      <header class="detail-head">
        <div class="node-identity"><span class="node-avatar"><Server :size="22" /></span><div><p class="eyebrow">节点设置</p><h3 id="node-dialog-title">{{ selectedNode.name || '未命名节点' }}</h3></div></div>
        <button class="icon-button" type="button" aria-label="关闭节点详情" @click="closeNodeDetail"><X :size="18" /></button>
      </header>
      <nav class="node-tabs" aria-label="节点配置分类">
        <button class="ghost" :class="{ selected: nodeDetailTab === 'directory' }" @click="nodeDetailTab = 'directory'">节点配置</button>
        <button v-if="selectedNode.capabilities.controller_administration_enabled" class="ghost" :class="{ selected: nodeDetailTab === 'permissions' }" @click="nodeDetailTab = 'permissions'">远程权限</button>
        <button v-if="selectedNode.capabilities.controller_administration_enabled" class="ghost" :class="{ selected: nodeDetailTab === 'admin' }" @click="nodeDetailTab = 'admin'">管理员</button>
        <button v-if="selectedNode.capabilities.remote_commands.block_ip" class="ghost" :class="{ selected: nodeDetailTab === 'ip' }" @click="nodeDetailTab = 'ip'">IP 控制</button>
      </nav>
      <div class="detail-body">
        <p v-if="!selectedNode.capabilities.controller_administration_enabled || !selectedNode.capabilities.remote_commands.change_runtime_settings" class="node-hint">需在边缘节点本地“多节点 → 本节点设置”授权中心管理及修改运行参数。未授权时仅查看，中心不会绕过授权改写目录。</p>
			  <div v-for="node in [selectedNode]" :key="node.node_id" class="form-grid node-edit-grid">
				<div class="span-all"><span class="pill" :class="node.connected ? 'active' : 'banned'">{{ node.connected ? 'mTLS 在线' : '离线' }}</span> <span class="pill" :class="node.capabilities.controller_administration_enabled ? 'active' : 'banned'">{{ node.capabilities.controller_administration_enabled ? '已授权远程管理' : '未授权远程管理' }}</span></div>
                <template v-if="nodeDetailTab === 'directory'">
                  <label class="span-all"><span>连接来源</span><input :value="node.last_remote_addr || '-'" readonly /></label>
                  <fieldset class="form-grid span-all enrollment-fields" :disabled="busy || !node.capabilities.controller_administration_enabled || !node.capabilities.remote_commands.change_runtime_settings">
                    <label><span>边缘节点名称</span><input v-model="node.capabilities.runtime_settings.tag" required maxlength="128" /></label>
                    <label><span>边缘公开 API URL</span><input v-model="node.capabilities.runtime_settings.public_api_url" placeholder="https://edge.example.com/api" /></label>
                    <label><span>边缘 frps 对外地址</span><input v-model="node.capabilities.runtime_settings.frp_advertise_addr" required /></label>
                    <label><span>边缘 frps 控制端口</span><input v-model.number="node.capabilities.runtime_settings.frp_bind_port" type="number" min="1" max="65535" required /></label>
                    <label><span>边缘端口池起始</span><input v-model.number="node.capabilities.runtime_settings.port_range_start" type="number" min="1" max="65535" required /></label>
                    <label><span>边缘端口池结束</span><input v-model.number="node.capabilities.runtime_settings.port_range_end" type="number" :min="node.capabilities.runtime_settings.port_range_start" max="65535" required /></label>
                    <label class="toggle-row span-all"><input v-model="node.capabilities.runtime_settings.selectable" type="checkbox" role="switch" /><span>允许获授权用户选择此边缘节点</span></label>
                    <button class="primary" type="button" @click="saveRemoteEdgeRuntime(node)">{{ busy ? '下发中…' : '通过 mTLS 保存节点配置' }}</button>
                  </fieldset>
                  <p class="settings-note span-all">在线节点确认保存后才更新中心目录；离线命令保留 10 分钟。修改监听端口后须重启该边缘节点。</p>
                  <button class="ghost" type="button" :disabled="busy || !node.capabilities.controller_administration_enabled || !node.capabilities.remote_commands.change_runtime_settings" @click="openRemoteAdvancedOptions(node)"><Settings :size="16" />此边缘节点的高级选项</button>
                </template>
				<template v-if="node.capabilities.controller_administration_enabled">
                <template v-if="nodeDetailTab === 'permissions'">
				  <div class="form-section span-all">中心远程修改 Edge 权限</div>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.client_presence" type="checkbox" role="switch" /><span>上报客户端状态</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.connections" type="checkbox" role="switch" /><span>上报连接详情</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.traffic_statistics" type="checkbox" role="switch" /><span>上报流量统计</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.dpi_events" type="checkbox" role="switch" /><span>上报 DPI 事件</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.reporting.runtime_logs" type="checkbox" role="switch" /><span>上报运行日志</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.disconnect_client" type="checkbox" role="switch" /><span>允许踢客户端</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.disconnect_connection" type="checkbox" role="switch" /><span>允许断开连接</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.block_ip" type="checkbox" role="switch" /><span>允许封禁 IP</span></label>
				  <label class="toggle-row"><input v-model="node.capabilities.remote_commands.change_runtime_settings" type="checkbox" role="switch" /><span>允许修改运行参数</span></label>
				  <button class="ghost" type="button" :disabled="busy" @click="saveRemoteEdgePermissions(node)">下发权限设置</button>
				  </template>
				  <template v-if="nodeDetailTab === 'admin'">
                  <div class="form-section span-all">修改 Edge 本地管理员</div>
				  <p class="span-all">密码仅在本次 HTTPS 请求和在线 mTLS 命令内存中短暂存在，不进入离线队列、MySQL 或审计详情。</p>
				  <label><span>管理员用户名</span><input v-model="edgeAdminForms[node.node_id].username" maxlength="64" /></label>
				  <label><span>显示名称</span><input v-model="edgeAdminForms[node.node_id].display_name" /></label>
				  <label><span>新密码</span><input v-model="edgeAdminForms[node.node_id].password" type="password" minlength="8" maxlength="72" autocomplete="new-password" /></label>
				  <label><span>确认新密码</span><input v-model="edgeAdminForms[node.node_id].password_confirm" type="password" minlength="8" maxlength="72" autocomplete="new-password" /></label>
				  <label class="span-all"><span>当前中心管理员密码（确认敏感操作）</span><input v-model="edgeAdminForms[node.node_id].controller_password" type="password" autocomplete="current-password" /></label>
				  <button class="primary" type="button" :disabled="busy || !node.connected || !edgeAdminForms[node.node_id].username || edgeAdminForms[node.node_id].password.length < 8" @click="rotateRemoteEdgeAdmin(node)">实时修改管理员凭据</button>
                  </template>
				</template>
			  </div>
        <form v-if="nodeDetailTab === 'ip'" class="form-grid" @submit.prevent="updateEdgeIPBlock('block_ip')">
          <p class="settings-note span-all">只作用于当前节点 {{ selectedNode.name }}。全局 IP 规则请在连接管理中配置。</p>
          <label><span>IP 地址</span><input v-model="edgeBlockForm.ip" required placeholder="203.0.113.10" /></label><label><span>原因</span><input v-model="edgeBlockForm.reason" /></label>
          <div class="actions span-all"><button class="primary" type="submit" :disabled="busy">封禁 IP</button><button class="ghost" type="button" :disabled="busy || !edgeBlockForm.ip" @click="updateEdgeIPBlock('unblock_ip')">解封 IP</button></div>
        </form>
        <section class="node-delete-zone">
          <div><h4>删除节点</h4><p>撤销中心接入资格，移除用户对该节点的授权，并清理中心保存的上报记录与待执行命令。重新接入需要新的 Token 注册。</p></div>
          <p>不会删除 Edge 上的程序或本地数据；已运行隧道可能继续运行，如需立即停机，请在 Edge 停止服务。</p>
          <button v-if="!confirmNodeDeletion" class="ghost danger-text" type="button" :disabled="busy" @click="confirmNodeDeletion = true"><Trash2 :size="16" />删除此节点</button>
          <form v-else class="form-grid" @submit.prevent="deleteSelectedNode">
            <label><span>输入“{{ selectedNode.name || selectedNode.node_id }}”确认删除（无法撤销）</span><input v-model="deleteNodeName" autocomplete="off" :placeholder="selectedNode.name || selectedNode.node_id" :disabled="busy" /></label>
            <div class="control-row"><button class="ghost danger-text" type="submit" :disabled="busy || deleteNodeName !== (selectedNode.name || selectedNode.node_id)"><Trash2 :size="16" />确认永久删除</button><button class="ghost" type="button" :disabled="busy" @click="confirmNodeDeletion = false; deleteNodeName = ''">取消</button></div>
          </form>
        </section>
      </div>
    </section>
  </div>
  </Transition>
  <Transition name="glass-modal" :duration="300">
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

        <section v-if="selectedUser.role === 'user'" class="detail-section">
          <h4>客户端 Token 与节点权限</h4>
          <p class="muted-text">用户 Token 在创建时由系统自动生成，可在下方凭证区域复制。客户端使用 Token 登录中心后选择授权节点，无需密码。</p>
          <p v-if="userNodeAccessLoading" class="muted-text">正在加载节点权限…</p>
          <form v-else-if="userNodeAccessReady" class="form-grid" @submit.prevent="saveUserNodeAccess">
            <div class="form-section">允许访问的节点</div>
            <label v-for="node in userNodeOptions" :key="node.node_id" class="toggle-row"><input v-model="userNodeIDs" type="checkbox" role="switch" :value="node.node_id" /><span>{{ node.name || node.node_id }}</span></label>
            <p v-if="!userNodeIDs.length" class="muted-text">当前未授权任何节点，此用户将无法建立隧道。</p>
            <button class="primary" type="submit" :disabled="busy"><ShieldCheck :size="16" />保存节点权限</button>
          </form>
          <button v-else class="ghost" type="button" @click="loadUserNodeAccess(selectedUser)">重新加载节点权限</button>
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
                <input v-model="policyForm.allowed_protocols" type="checkbox" role="switch" :value="protocol" />
                <span>{{ protocol }}</span>
              </label>
            </div>
            <label class="toggle-row">
              <input v-model="policyForm.enabled" type="checkbox" role="switch" />
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
              <input v-model="dpiForm.enabled" type="checkbox" role="switch" />
              <span>启用此用户的 DPI 策略</span>
            </label>
            <button class="primary" type="button" :disabled="busy" @click="saveDpiGateway(selectedUser.id, dpiForm.enabled)">
              <ShieldCheck :size="18" />
              保存启用状态
            </button>
            <button class="ghost" type="button" @click="openDpiConfig(selectedUser)">
              <Settings :size="18" />
              配置策略
            </button>
          </div>
          <UserCacheSync v-if="deploymentMode === 'controller'" :user-id="selectedUser.id" :refresh-version="cacheSyncRefreshVersion" :fetch-states="fetchUserCacheStates" />
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

  </Transition>
  <Transition name="glass-modal" :duration="300">
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
        <label v-if="userForm.role === 'admin'"><span>管理员密码</span><input v-model="userForm.password" required minlength="8" maxlength="72" type="password" autocomplete="new-password" placeholder="至少 8 位" /></label>
        <p v-if="userForm.role === 'user'" class="muted-text">普通用户创建后自动生成唯一 Token 和默认资源策略，无需密码。请在用户详情中复制 Token，并勾选允许访问的节点。</p>
        <button class="primary" type="submit" :disabled="busy">
          <Plus :size="18" />
          创建用户
        </button>
      </form>
    </section>
  </div>

  </Transition>
  <Transition name="glass-toast">
    <div v-if="toast" :key="toast" class="toast" role="status" aria-live="polite">{{ toast }}</div>
  </Transition>
</template>
