<template>
  <div class="category-list card">
    <div class="list-header">
      <h3>&#x1F4C2; 检查分类</h3>
      <div class="tab-toggle">
        <button
          class="tab-btn"
          :class="{ active: activeTab === 'findings' }"
          @click="$emit('update:activeTab', 'findings')"
        >
          发现
        </button>
        <button
          class="tab-btn"
          :class="{ active: activeTab === 'dvwa' }"
          @click="$emit('update:activeTab', 'dvwa')"
        >
          DVWA
        </button>
      </div>
    </div>

    <div v-if="activeTab === 'findings'" class="category-items">
      <button
        v-for="cat in categoryList"
        :key="cat.name"
        class="category-item"
        :class="{ active: selectedCategory === cat.name }"
        @click="$emit('update:selectedCategory', cat.name)"
      >
        <span class="cat-name">{{ cat.name }}</span>
        <span class="cat-count">
          <span class="severity-dot" :class="'severity-' + cat.maxSeverity"></span>
          {{ cat.count }}
        </span>
      </button>
    </div>

    <div v-else-if="activeTab === 'dvwa'" class="category-items">
      <p class="hint-text">DVWA 覆盖情况请查看右侧面板。</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Finding } from '@/types/models'

const props = defineProps<{
  findings: Finding[]
  selectedCategory: string
  activeTab: 'findings' | 'dvwa'
}>()

defineEmits<{
  'update:selectedCategory': [value: string]
  'update:activeTab': [value: 'findings' | 'dvwa']
}>()

const severityPriority: Record<string, number> = {
  高: 0,
  中: 1,
  低: 2,
  信息: 3,
}

const categoryList = computed(() => {
  const map = new Map<string, { name: string; count: number; maxSeverity: string }>()
  props.findings.forEach((f: Finding) => {
    const existing = map.get(f.category)
    if (existing) {
      existing.count++
      if (severityPriority[f.severity] < severityPriority[existing.maxSeverity]) {
        existing.maxSeverity = f.severity
      }
    } else {
      map.set(f.category, { name: f.category, count: 1, maxSeverity: f.severity })
    }
  })
  return Array.from(map.values()).sort((a, b) => {
    return severityPriority[a.maxSeverity] - severityPriority[b.maxSeverity]
  })
})
</script>

<style scoped>
.category-list {
  padding: 0;
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.list-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px;
  border-bottom: 1px solid var(--border-color);
}

.list-header h3 {
  font-size: 0.95rem;
  font-weight: 600;
}

.tab-toggle {
  display: flex;
  background: var(--bg-tertiary);
  border-radius: var(--radius-sm);
  padding: 2px;
}

.tab-btn {
  padding: 4px 12px;
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-secondary);
  background: none;
  border-radius: 4px;
}

.tab-btn.active {
  background: var(--accent-blue);
  color: white;
}

.category-items {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
}

.category-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 10px 12px;
  background: none;
  border-radius: var(--radius-sm);
  color: var(--text-primary);
  font-size: 0.9rem;
  text-align: left;
}

.category-item:hover {
  background: var(--bg-hover);
}

.category-item.active {
  background: rgba(88, 166, 255, 0.1);
  color: var(--accent-blue);
}

.cat-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.cat-count {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 0.85rem;
}

.severity-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}

.hint-text {
  padding: 16px;
  color: var(--text-muted);
  font-size: 0.9rem;
  text-align: center;
}
</style>
