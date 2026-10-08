<script setup lang="ts">
import { onMounted, onUnmounted, ref, useId } from 'vue'
import { Settings, X } from '@lucide/vue'
const props = defineProps<{ title: string; busy?: boolean }>()
const emit = defineEmits<{ close: [] }>()
const titleID = useId()
const dialog = ref<HTMLElement | null>(null)
let focusBefore: HTMLElement | null = null
let overflowBefore = ''
onMounted(() => {
  focusBefore = document.activeElement instanceof HTMLElement ? document.activeElement : null
  overflowBefore = document.body.style.overflow
  document.body.style.overflow = 'hidden'
  dialog.value?.focus()
})
onUnmounted(() => { document.body.style.overflow = overflowBefore; focusBefore?.focus() })
function handleKey(event: KeyboardEvent) {
  if (event.key === 'Escape') { event.preventDefault(); if (!props.busy) emit('close'); return }
  if (event.key !== 'Tab' || !dialog.value) return
  const controls = [...dialog.value.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), textarea:not(:disabled), select:not(:disabled), summary')].filter(el => el.getClientRects().length)
  const first = controls[0], last = controls.at(-1)
  if (!first || !last) { event.preventDefault(); return }
  if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog.value)) { event.preventDefault(); last.focus() }
  else if (!event.shiftKey && (document.activeElement === last || document.activeElement === dialog.value)) { event.preventDefault(); first.focus() }
}
</script>
<template>
  <div class="modal-backdrop" @click.self="!busy && emit('close')">
    <section ref="dialog" class="detail-modal settings-dialog" role="dialog" aria-modal="true" :aria-labelledby="titleID" tabindex="-1" @keydown="handleKey">
      <header class="detail-head"><div class="node-identity"><span class="node-avatar"><Settings :size="22" /></span><h3 :id="titleID">{{ title }}</h3></div><button class="icon-button" type="button" :disabled="busy" aria-label="关闭窗口" @click="emit('close')"><X :size="18" /></button></header>
      <div class="settings-dialog-body"><slot /></div>
    </section>
  </div>
</template>
