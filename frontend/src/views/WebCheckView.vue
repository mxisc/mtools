<template>
  <div class="webcheck-view">
    <div v-if="!wailsAvailable" class="backend-warning">
      <div class="warning-icon">!</div>
      <div class="warning-content">
        <h3>Wails 后端未连接</h3>
        <p>当前仅在开发模式下运行前端，后端不可用。请使用以下方式之一运行完整应用：</p>
        <div class="warning-actions">
          <code>wails dev</code>
          <span class="or">或</span>
          <code>运行编译后的应用</code>
        </div>
      </div>
    </div>

    <div class="input-section card">
      <h2 class="section-title">&#x1F512; Web 安全检查</h2>
      <div class="input-row">
        <input
          v-model="target"
          type="text"
          placeholder="输入目标 URL，例如 http://testphp.vulnweb.com"
          class="target-input"
          @keyup.enter="startCheck"
        />
        <button
          class="btn btn-primary btn-lg"
          :disabled="isLoading || !target"
          @click="startCheck"
        >
          <span v-if="isLoading" class="spinner"></span>
          {{ isLoading ? '检查中...' : '开始检查' }}
        </button>
        <button
          v-if="isLoading"
          class="btn btn-danger btn-lg"
          @click="handleStop"
        >
          停止
        </button>
      </div>
    </div>

    <div v-if="error" class="error-banner mt-2">
      &#x26A0;&#xFE0F; {{ error }}
    </div>

    <template v-if="result">
      <DashboardPanel :result="result" />

      <div class="split-layout mt-3">
        <CategoryList
          :findings="result.findings"
          v-model:selectedCategory="selectedCategory"
          v-model:activeTab="activeTab"
        />
        <DetailPanel
          :findings="filteredFindings"
          :dvwaCoverage="result.dvwaCoverage"
          :activeTab="activeTab"
        />
      </div>
    </template>

    <div v-else-if="!isLoading" class="empty-state mt-3">
      <div class="icon">&#x1F512;</div>
      <p>请输入目标 URL 并开始 Web 安全检查</p>
      <p class="sub">系统将自动检测安全配置、HTTP 头、TLS 等信息</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import type { Finding, WebCheckResult } from '@/types/models'
import { runWebCheck, stopTask, isWailsAvailable } from '@/api/wails'
import DashboardPanel from '@/components/webcheck/DashboardPanel.vue'
import CategoryList from '@/components/webcheck/CategoryList.vue'
import DetailPanel from '@/components/webcheck/DetailPanel.vue'

const wailsAvailable = ref(false)

const target = ref('')
const isLoading = ref(false)
const error = ref('')
const result = ref<WebCheckResult | null>(null)
const selectedCategory = ref('')
const activeTab = ref<'findings' | 'dvwa'>('findings')

import { onMounted } from 'vue'
onMounted(() => {
  wailsAvailable.value = isWailsAvailable()
})

const categories = computed(() => {
  if (!result.value) return []
  const cats = new Set(result.value.findings.map((f: Finding) => f.category))
  return Array.from(cats)
})

const filteredFindings = computed(() => {
  if (!result.value) return []
  if (!selectedCategory.value) return result.value.findings
  return result.value.findings.filter((f: Finding) => f.category === selectedCategory.value)
})

async function startCheck() {
  if (!target.value || isLoading.value) return
  isLoading.value = true
  error.value = ''
  result.value = null
  selectedCategory.value = ''
  activeTab.value = 'findings'

  try {
    const data = await runWebCheck(target.value)
    result.value = data as WebCheckResult
    if (categories.value.length > 0) {
      selectedCategory.value = categories.value[0]
    }
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    error.value = `检查失败: ${msg}`
  } finally {
    isLoading.value = false
  }
}

async function handleStop() {
  try {
    await stopTask()
  } catch {
  }
  isLoading.value = false
}
</script>

<style scoped>
.webcheck-view {
  max-width: 1400px;
  margin: 0 auto;
}

.input-section {
  padding: 24px;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 700;
  margin-bottom: 16px;
}

.input-row {
  display: flex;
  gap: 12px;
  align-items: center;
}

.target-input {
  flex: 1;
  padding: 12px 16px;
  font-size: 0.95rem;
  font-family: var(--font-mono);
}

.error-banner {
  background: rgba(248, 81, 73, 0.1);
  border: 1px solid rgba(248, 81, 73, 0.3);
  color: var(--accent-red);
  padding: 12px 16px;
  border-radius: var(--radius-sm);
  font-size: 0.9rem;
}

.split-layout {
  display: grid;
  grid-template-columns: 300px 1fr;
  gap: 20px;
  min-height: 500px;
}

@media (max-width: 900px) {
  .split-layout {
    grid-template-columns: 1fr;
  }
}

.backend-warning {
  background: rgba(255, 193, 7, 0.08);
  border: 1px solid rgba(255, 193, 7, 0.3);
  border-radius: var(--radius-md);
  padding: 20px 24px;
  margin-bottom: 20px;
  display: flex;
  align-items: flex-start;
  gap: 16px;
}

.warning-icon {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: rgba(255, 193, 7, 0.2);
  color: #ffc107;
  font-weight: 900;
  font-size: 1.1rem;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.warning-content h3 {
  color: #ffc107;
  font-size: 1rem;
  font-weight: 700;
  margin-bottom: 6px;
}

.warning-content p {
  color: var(--text-secondary);
  font-size: 0.9rem;
  margin-bottom: 10px;
}

.warning-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 0.85rem;
}

.warning-actions code {
  background: rgba(0, 0, 0, 0.3);
  padding: 4px 10px;
  border-radius: var(--radius-sm);
  color: var(--accent-green);
  font-family: var(--font-mono);
}

.warning-actions .or {
  color: var(--text-secondary);
}
</style>
