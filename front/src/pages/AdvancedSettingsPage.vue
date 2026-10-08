<script setup lang="ts">
import { computed, nextTick, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Settings, ShieldCheck, Sparkles, RefreshCw } from '@lucide/vue'
import type { AdvancedSettings, ConfigurationMode } from '../types/advancedSettings'

const props = defineProps<{ settings: AdvancedSettings; busy: boolean; error: string; notice: string; dirty: boolean; frpsRunning: boolean | null; nodeLabel?: string; remote?: boolean }>()
const emit = defineEmits<{ close: []; save: []; reload: []; mode: [mode: ConfigurationMode] }>()
const automatic = computed(() => props.settings.configuration_mode === 'automatic')
const route = useRoute()
const router = useRouter()
const form = ref<HTMLFormElement | null>(null)
const categories = computed(() => [
  { id: 'frp', title: 'FRP 与监听', description: '服务启停、TLS 和监听地址' },
  { id: 'timeouts', title: '鉴权与超时', description: '会话、租约和 UDP 有效期' },
  { id: 'tcp', title: 'TCP 连接', description: '多路复用、保活和连接池' },
  { id: 'mtls', title: 'mTLS 管理通道', description: '握手与快速会话恢复' },
  ...(!props.remote ? [{ id: 'file', title: '启动信息', description: 'cfg 路径和环境变量说明' }] : []),
])
const category = computed(() => categories.value.some(item => item.id === route.params.section) ? String(route.params.section) : 'frp')
function categoryRoute(id: string) { return { name: route.name!, params: { ...route.params, section: id } } }
async function save() {
  if (props.busy) return
  // Validate all categories, then reveal/focus an invalid field before saving.
  const invalid = form.value?.querySelector<HTMLInputElement>('input:invalid')
  if (invalid) {
    const section = invalid.closest<HTMLElement>('[data-category]')?.dataset.category
    if (section) await router.replace(categoryRoute(section))
    await nextTick()
    invalid.focus()
    invalid.reportValidity()
    return
  }
  emit('save')
}
const tcpMuxEnabled = computed({ get: () => !props.settings.connection_tuning.disable_tcp_mux, set: value => { props.settings.connection_tuning.disable_tcp_mux = !value } })
const sessionTicketsEnabled = computed({ get: () => !props.settings.connection_tuning.disable_mtls_session_tickets, set: value => { props.settings.connection_tuning.disable_mtls_session_tickets = !value } })
</script>

<template>
    <section class="advanced-settings-page" aria-labelledby="advanced-title">
      <header class="panel advanced-page-head">
        <div class="node-identity"><span class="node-avatar"><Settings :size="22" /></span><div><p class="eyebrow">运行配置 · {{ nodeLabel || (settings.mode === 'edge' ? '本边缘节点' : '中心节点') }}</p><h3 id="advanced-title">{{ remote ? '边缘节点高级选项' : '高级选项' }}</h3></div></div>
        <button class="ghost" type="button" :disabled="busy" @click="emit('close')"><ArrowLeft :size="17" />{{ remote ? '返回节点列表' : '返回系统设置' }}</button>
      </header>
      <nav class="advanced-category-nav" aria-label="高级设置分类">
        <RouterLink v-for="item in categories" :key="item.id" :to="categoryRoute(item.id)" :class="{ selected: category === item.id }" :aria-current="category === item.id ? 'page' : undefined"><strong>{{ item.title }}</strong><small>{{ item.description }}</small></RouterLink>
      </nav>
      <form ref="form" class="advanced-page-form" novalidate @submit.prevent="save">
        <section class="panel advanced-mode-panel">
        <div class="advanced-mode-selector" aria-label="配置模式">
          <button class="ghost" :class="{ selected: automatic }" type="button" :disabled="busy" :aria-pressed="automatic" @click="emit('mode', 'automatic')"><Sparkles :size="17" />自动推荐</button>
          <button class="ghost" :class="{ selected: !automatic }" type="button" :disabled="busy" :aria-pressed="!automatic" @click="emit('mode', 'manual')"><Settings :size="17" />手动配置</button>
        </div>
        <p class="settings-note">{{ automatic ? '自动保持内置 FRP 开启、FRP TLS 关闭，不自动重置底层调优。未调整的项目沿用原默认值。' : '手动控制 FRP 启停和 TLS；底层参数保存到 cfg，重启后保留。' }} 正常节点接入和权限管理请使用“多节点”选项卡。</p>
        </section>
        <div v-if="error" class="alert danger" role="alert">{{ error }}</div>
        <div v-if="notice" class="alert warning" role="status">{{ notice }}</div>
        <p v-if="remote" class="settings-note">此处只修改 {{ nodeLabel }}，通过 mTLS 下发，不会修改中心设置。在线确认后提示已保存；离线命令保留 10 分钟。启停、TLS 与监听调优须重启该边缘节点。</p>
        <p v-else class="advanced-status">内置 FRP 当前进程：<span class="pill" :class="frpsRunning ? 'active' : 'banned'">{{ frpsRunning === null ? '未知' : frpsRunning ? '运行中' : '未运行' }}</span>启停、TLS 和监听参数保存后需要重启后端。</p>

        <section v-show="category === 'frp'" class="panel advanced-category" data-category="frp">
          <header><h4>FRP 与监听</h4><p>自动模式仅锁定服务开启和 TLS 关闭；其余参数可独立调整。</p></header>
          <fieldset class="form-grid" :disabled="busy">
            <label class="toggle-row span-all"><input v-model="settings.embedded_frps_enabled" type="checkbox" role="switch" :disabled="automatic" /><span>启用内置 FRP 服务</span></label>
            <label class="toggle-row span-all"><input v-model="settings.frp_transport_tls" type="checkbox" role="switch" :disabled="automatic" /><span>启用客户端 FRP TLS（手动可选，默认关闭）</span></label>
            <label><span>FRP 控制监听地址</span><input v-model="settings.frp_bind_addr" placeholder="0.0.0.0" required /></label>
            <label><span>隧道端口监听地址</span><input v-model="settings.frp_proxy_bind_addr" placeholder="0.0.0.0" required /></label>
            <label class="span-all"><span>客户端配置注释</span><input v-model="settings.client_config_comment" maxlength="512" /></label>
          </fieldset>
          <p class="settings-note">{{ settings.mode === 'controller' ? '中心对外地址、控制端口和端口池在系统设置中配置。' : '边缘对外地址、控制端口和端口池在该节点的设置中配置。' }} FRP TLS 与 9443 的节点 mTLS 是两条独立连接。</p>
        </section>

        <section v-show="category === 'timeouts'" class="panel advanced-category" data-category="timeouts">
          <header><h4>鉴权与超时</h4><p>仅修改当前目标节点的时长配置。</p></header>
          <fieldset class="form-grid" :disabled="busy">
            <label><span>管理员会话有效期</span><input v-model="settings.session_ttl" placeholder="1h" required /></label>
            <label><span>隧道租约有效期</span><input v-model="settings.runtime_token_ttl" placeholder="24h" required /></label>
            <label><span>UDP 连接超时</span><input v-model="settings.udp_connection_ttl" placeholder="10s" required /></label>
          </fieldset>
          <p class="settings-note">支持 Go 时长格式，如 30m、1h、24h。现有租约不会因修改有效期而立即重新签发。</p>
        </section>

        <section v-show="category === 'tcp'" class="panel advanced-category" data-category="tcp">
          <header><h4>TCP 连接与连接池调优</h4><p>0 沿用原默认值；调整前请确认客户端与服务端兼容。</p></header>
          <fieldset class="form-grid" :disabled="busy">
            <label class="toggle-row span-all"><input v-model="tcpMuxEnabled" type="checkbox" role="switch" /><span>TCP 多路复用</span></label>
            <label><span>多路复用保活（秒）</span><input v-model.number="settings.connection_tuning.tcp_mux_keepalive_seconds" type="number" min="0" max="3600" required /></label>
            <label><span>TCP Keepalive（秒）</span><input v-model.number="settings.connection_tuning.tcp_keepalive_seconds" type="number" min="-1" max="86400" required /></label>
            <label><span>每个隧道最大连接池</span><input v-model.number="settings.connection_tuning.max_pool_count" type="number" min="0" max="1024" required /></label>
            <label><span>FRP 心跳超时（秒）</span><input v-model.number="settings.connection_tuning.heartbeat_timeout_seconds" type="number" min="-1" max="3600" required /></label>
            <label><span>等待工作连接超时（秒）</span><input v-model.number="settings.connection_tuning.user_connection_timeout_seconds" type="number" min="0" max="600" required /></label>
          </fieldset>
          <p class="settings-note">0 沿用 FRP 原默认值：多路保活 30 秒、TCP Keepalive 7200 秒、连接池上限 5、工作连接等待 10 秒；TCP Keepalive / 心跳超时的 -1 表示关闭对应检测。不要将心跳超时设得短于客户端心跳间隔。修改多路复用后请重启服务并重新下发客户端配置。</p>
        </section>

        <section v-show="category === 'mtls'" class="panel advanced-category" data-category="mtls">
          <header><h4>mTLS 握手与快速会话恢复</h4><p>中心监听与边缘缓存分别配置，不替换证书、不跳过鉴权。</p></header>
          <fieldset class="form-grid" :disabled="busy">
            <template v-if="settings.mode === 'controller'">
              <label><span>mTLS 握手 / 请求头超时（秒）</span><input v-model.number="settings.connection_tuning.mtls_handshake_timeout_seconds" type="number" min="0" max="120" required /></label>
              <label class="toggle-row span-all"><input v-model="sessionTicketsEnabled" type="checkbox" role="switch" /><span>允许边缘节点通过 TLS 会话票据恢复连接</span></label>
            </template>
            <label v-else class="toggle-row span-all"><input v-model="settings.connection_tuning.enable_mtls_session_resumption" type="checkbox" role="switch" /><span>快速 mTLS 会话恢复（缓存 TLS 会话）</span></label>
          </fieldset>
          <p class="settings-note">中心握手超时 0 沿用 10 秒。快速恢复需中心允许票据且边缘节点启用缓存，只加速本进程重连握手，不跳过证书和节点身份校验、不恢复已断开的 FRP 隧道。默认不启用边缘会话缓存；这些参数修改后需重启。</p>
        </section>

        <section v-if="!remote" v-show="category === 'file'" class="panel advanced-category" data-category="file">
          <header><h4>配置文件与启动信息</h4><p>运行信息只读，敏感材料通过专用流程管理。</p></header>
          <div class="advanced-file-info"><p>cfg 路径：<code>{{ settings.config_path || '未提供' }}</code></p><p>当前 API 监听：<code>{{ settings.http_addr || '未提供' }}</code></p><p>API 监听由启动参数或环境变量控制；环境变量优先级高于 cfg。数据库密码、Token、Cookie 密钥及证书私钥不在此编辑，请使用对应的初始化、数据库修复或证书管理流程。</p></div>
        </section>

        <footer class="panel settings-save-bar advanced-save-bar"><p>{{ dirty ? '有未保存修改' : '无未保存修改' }} · 保存会提交全部分类，离开前会提醒未保存内容。</p><div class="actions"><button class="ghost" type="button" :disabled="busy" @click="emit('reload')"><RefreshCw :size="16" />重新读取</button><button class="primary" type="submit" :disabled="busy"><ShieldCheck :size="17" />{{ busy ? '保存中…' : remote ? '通过 mTLS 下发' : '保存高级设置' }}</button></div></footer>
      </form>
    </section>
</template>
