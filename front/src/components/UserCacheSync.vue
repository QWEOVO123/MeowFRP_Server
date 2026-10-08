<script setup lang="ts">
import { onUnmounted, ref, watch } from 'vue'
import { RefreshCw } from '@lucide/vue'
import type { CacheNodeState } from '../types/userCacheSync'

const props = defineProps<{
  userId: number
  refreshVersion: number
  fetchStates: (userID: number) => Promise<CacheNodeState[]>
}>()
const nodes = ref<CacheNodeState[]>([])
const loading = ref(false)
const error = ref('')
let generation = 0
async function refresh() {
  const request = ++generation
  nodes.value = []
  error.value = ''
  if (!props.userId) { loading.value = false; return }
  loading.value = true
  try {
    const result = await props.fetchStates(props.userId)
    if (request === generation) nodes.value = result
  } catch (cause) {
    if (request === generation) error.value = cause instanceof Error ? cause.message : '同步状态读取失败'
  } finally {
    if (request === generation) loading.value = false
  }
}
watch(() => [props.userId, props.refreshVersion], () => { void refresh() }, { immediate: true })
onUnmounted(() => { ++generation })
</script>

<template>
  <div v-if="userId" class="cache-sync" aria-live="polite">
    <div class="sync-head">
      <strong>边缘用户信息 / DPI 同步</strong>
      <button class="ghost" type="button" :disabled="loading" @click="refresh"><RefreshCw :size="15" />刷新状态</button>
    </div>
    <p>中心主动推送，节点落盘确认后才显示已同步；这里刷新只查询中心记录，不轮询边缘。</p>
    <p v-if="error" class="sync-error">{{ error }}</p>
    <p v-else-if="loading">正在读取同步状态…</p>
    <p v-else-if="!nodes.length">尚无边缘缓存记录；节点接入并完成同步后会显示。</p>
    <div v-for="node in nodes" :key="node.node_id" class="sync-node">
      <span>{{ node.node_name || node.node_id }}<small>{{ node.online ? '在线' : '离线' }}</small></span>
      <span class="pill" :class="node.pending ? 'banned' : 'active'">{{ node.pending ? (node.online ? '待节点确认' : '待上线同步') : (node.cached ? '已同步' : '未缓存') }}</span>
      <code>已确认 {{ node.applied_revision }} / 目标 {{ node.desired_revision }}</code>
    </div>
  </div>
</template>

<style scoped>
.cache-sync { margin-top: 16px; padding: 16px; border: 1px solid rgba(75, 143, 232, .24); border-radius: 14px; background: rgba(225, 239, 255, .42); }
.sync-head, .sync-node { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.sync-head { justify-content: space-between; }
.cache-sync p, .sync-node small, .sync-node code { color: #52677f; font-size: 12px; }
.sync-node { padding: 10px 0; border-top: 1px solid rgba(75, 143, 232, .16); }
.sync-node small { margin-left: 8px; }
.sync-error { color: #b44343 !important; }
</style>
