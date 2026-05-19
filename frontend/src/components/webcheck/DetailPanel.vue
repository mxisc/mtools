<template>
  <div class="detail-panel card">
    <template v-if="activeTab === 'findings'">
      <div class="panel-header">
        <h3>&#x1F4DD; 检查发现</h3>
        <span class="count-badge">{{ findings.length }} 项</span>
      </div>

      <div v-if="findings.length === 0" class="empty-state">
        <div class="icon">&#x2728;</div>
        <p>未发现问题</p>
      </div>

      <div class="findings-list">
        <div
          v-for="(finding, index) in findings"
          :key="index"
          class="finding-item"
        >
          <div class="finding-header">
            <span class="finding-title">{{ finding.title }}</span>
            <span class="badge" :class="'badge-' + finding.severity">
              {{ getSeverityLabel(finding.severity) }}
            </span>
          </div>
          <div class="finding-body">
            <div class="finding-section">
              <span class="section-label">详情</span>
              <p class="section-content">{{ finding.details }}</p>
            </div>
            <div v-if="finding.evidence" class="finding-section">
              <span class="section-label">证据</span>
              <pre class="evidence-block">{{ finding.evidence }}</pre>
            </div>
            <div v-if="finding.recommendation" class="finding-section">
              <span class="section-label">建议</span>
              <p class="section-content recommend">{{ finding.recommendation }}</p>
            </div>
          </div>
        </div>
      </div>
    </template>

    <template v-else-if="activeTab === 'dvwa'">
      <div class="panel-header">
        <h3>&#x1F3AF; DVWA 覆盖情况</h3>
      </div>

      <div v-if="dvwaCoverage.length === 0" class="empty-state">
        <div class="icon">&#x1F4E6;</div>
        <p>暂无 DVWA 覆盖数据</p>
      </div>

      <div v-else class="dvwa-grid">
        <div
          v-for="(item, index) in dvwaCoverage"
          :key="index"
          class="dvwa-item"
        >
          <div class="dvwa-name">{{ item.name }}</div>
          <div class="dvwa-status">
            <span class="badge" :class="'badge-' + item.status">
              {{ getCoverageLabel(item.status) }}
            </span>
          </div>
          <div v-if="item.notes" class="dvwa-notes">{{ item.notes }}</div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { Finding, CoverageItem } from '@/types/models'
import { getSeverityLabel, getCoverageLabel } from '@/utils/helpers'

defineProps<{
  findings: Finding[]
  dvwaCoverage: CoverageItem[]
  activeTab: 'findings' | 'dvwa'
}>()
</script>

<style scoped>
.detail-panel {
  padding: 0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.panel-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  border-bottom: 1px solid var(--border-color);
}

.panel-header h3 {
  font-size: 0.95rem;
  font-weight: 600;
}

.count-badge {
  padding: 2px 10px;
  background: var(--bg-tertiary);
  border-radius: 20px;
  font-size: 0.8rem;
  color: var(--text-secondary);
}

.findings-list {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
}

.finding-item {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  margin-bottom: 12px;
  overflow: hidden;
}

.finding-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 14px;
  background: var(--bg-hover);
}

.finding-title {
  font-weight: 600;
  font-size: 0.95rem;
}

.finding-body {
  padding: 14px;
}

.finding-section {
  margin-bottom: 12px;
}

.finding-section:last-child {
  margin-bottom: 0;
}

.section-label {
  display: block;
  font-size: 0.75rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 4px;
}

.section-content {
  font-size: 0.9rem;
  color: var(--text-secondary);
  line-height: 1.6;
}

.section-content.recommend {
  color: var(--accent-cyan);
}

.evidence-block {
  background: var(--bg-primary);
  border: 1px solid var(--border-color);
  border-radius: 4px;
  padding: 10px 12px;
  font-family: var(--font-mono);
  font-size: 0.82rem;
  color: var(--accent-green);
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 200px;
  overflow-y: auto;
}

.dvwa-grid {
  flex: 1;
  overflow-y: auto;
  padding: 12px;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 10px;
  align-content: start;
}

.dvwa-item {
  background: var(--bg-tertiary);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-sm);
  padding: 14px;
}

.dvwa-name {
  font-weight: 600;
  font-size: 0.95rem;
  margin-bottom: 6px;
}

.dvwa-status {
  margin-bottom: 6px;
}

.dvwa-notes {
  font-size: 0.82rem;
  color: var(--text-muted);
  line-height: 1.5;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 24px;
  color: var(--text-muted);
  flex: 1;
}

.empty-state .icon {
  font-size: 3rem;
  margin-bottom: 12px;
  opacity: 0.5;
}

.empty-state p {
  font-size: 0.95rem;
}
</style>
