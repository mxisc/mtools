<template>
  <div class="dashboard-panel">
    <div class="dashboard-grid">
      <div class="card target-info">
        <h3>&#x1F4CB; 目标信息</h3>
        <div class="info-grid">
          <div class="info-item">
            <span class="label">检查时间</span>
            <span class="value">{{ formatTime(result.checkedAt) }}</span>
          </div>
          <div class="info-item">
            <span class="label">目标地址</span>
            <span class="value mono">{{ result.target }}</span>
          </div>
          <div class="info-item">
            <span class="label">最终 URL</span>
            <span class="value mono">{{ result.finalUrl || result.target }}</span>
          </div>
          <div class="info-item">
            <span class="label">HTTP 状态码</span>
            <span class="value">
              <span class="status-badge" :class="statusClass(result.statusCode)">
                {{ result.statusCode }}
              </span>
            </span>
          </div>
          <div class="info-item">
            <span class="label">HTTPS</span>
            <span class="value">
              <span class="bool-badge" :class="result.usesHttps ? 'yes' : 'no'">
                {{ result.usesHttps ? '是' : '否' }}
              </span>
            </span>
          </div>
          <div class="info-item">
            <span class="label">TLS 版本</span>
            <span class="value mono">{{ result.tlsVersion || '-' }}</span>
          </div>
          <div class="info-item">
            <span class="label">HTTP 跳转 HTTPS</span>
            <span class="value">
              <span class="bool-badge" :class="result.httpRedirectsToHttps ? 'yes' : 'no'">
                {{ result.httpRedirectsToHttps ? '是' : '否' }}
              </span>
            </span>
          </div>
          <div class="info-item">
            <span class="label">支持的 HTTP 方法</span>
            <span class="value mono">{{ result.supportedMethods.join(', ') || '-' }}</span>
          </div>
        </div>
      </div>

      <div class="card score-card">
        <h3>&#x1F4CA; 安全评分</h3>
        <div class="score-circle" :style="{ '--score': score, '--score-color': scoreColor }">
          <div class="score-value">{{ score }}</div>
          <div class="score-label">/ 100</div>
        </div>
        <div class="score-desc">{{ scoreMessage }}</div>
      </div>

      <div class="card severity-stats">
        <h3>&#x1F6A8; 风险统计</h3>
        <div class="severity-bars">
          <div
            v-for="s in severityOrder"
            :key="s"
            class="severity-row"
          >
            <span class="sev-label">
              <span class="severity-dot" :class="'severity-' + s"></span>
              {{ severityLabel(s) }}
            </span>
            <span class="sev-count">{{ severityCounts[s] || 0 }}</span>
          </div>
        </div>
        <div class="severity-summary">
          共发现 <strong>{{ result.findings.length }}</strong> 项问题
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { WebCheckResult, Finding } from '@/types/models'
import { getSeverityLabel } from '@/utils/helpers'

const props = defineProps<{
  result: WebCheckResult
}>()

const severityOrder = ['高', '中', '低', '信息'] as const

const severityCounts = computed(() => {
  const counts: Record<string, number> = {}
  props.result.findings.forEach((f: Finding) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1
  })
  return counts
})

const score = computed(() => {
  const weights: Record<string, number> = {
    高: 15,
    中: 8,
    低: 3,
    信息: 0,
  }
  let deduction = 0
  props.result.findings.forEach((f: Finding) => {
    deduction += weights[f.severity] || 0
  })
  return Math.max(0, 100 - deduction)
})

const scoreColor = computed(() => {
  if (score.value >= 80) return 'var(--accent-green)'
  if (score.value >= 60) return 'var(--accent-yellow)'
  if (score.value >= 40) return 'var(--accent-orange)'
  return 'var(--accent-red)'
})

const scoreMessage = computed(() => {
  if (score.value >= 90) return '安全评分优秀，继续保持'
  if (score.value >= 70) return '存在一定风险，建议修复'
  if (score.value >= 50) return '存在较多风险，需要整改'
  return '安全风险较高，请立即处理'
})

function severityLabel(sev: string): string {
  return getSeverityLabel(sev)
}

function statusClass(code: number): string {
  if (code >= 200 && code < 300) return 'ok'
  if (code >= 300 && code < 400) return 'redirect'
  if (code >= 400 && code < 500) return 'client-error'
  if (code >= 500) return 'server-error'
  return ''
}

function formatTime(dateStr: string): string {
  try {
    return new Date(dateStr).toLocaleString('zh-CN')
  } catch {
    return dateStr
  }
}
</script>

<style scoped>
.dashboard-grid {
  display: grid;
  grid-template-columns: 1fr 200px 200px;
  gap: 16px;
}

@media (max-width: 1100px) {
  .dashboard-grid {
    grid-template-columns: 1fr 1fr;
  }
  .score-card {
    grid-column: 1 / -1;
  }
}

@media (max-width: 700px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
  }
}

.target-info h3,
.score-card h3,
.severity-stats h3 {
  font-size: 0.95rem;
  font-weight: 600;
  margin-bottom: 14px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border-color);
}

.info-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px 20px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.info-item .label {
  font-size: 0.75rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.info-item .value {
  font-size: 0.9rem;
  color: var(--text-primary);
}

.info-item .value.mono {
  font-family: var(--font-mono);
  font-size: 0.85rem;
}

.status-badge {
  padding: 2px 10px;
  border-radius: 4px;
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 0.85rem;
}

.status-badge.ok {
  background: rgba(63, 185, 80, 0.15);
  color: var(--accent-green);
}

.status-badge.redirect {
  background: rgba(88, 166, 255, 0.15);
  color: var(--accent-blue);
}

.status-badge.client-error {
  background: rgba(210, 153, 34, 0.15);
  color: var(--accent-yellow);
}

.status-badge.server-error {
  background: rgba(248, 81, 73, 0.15);
  color: var(--accent-red);
}

.bool-badge {
  padding: 2px 10px;
  border-radius: 4px;
  font-weight: 600;
  font-size: 0.85rem;
}

.bool-badge.yes {
  background: rgba(63, 185, 80, 0.15);
  color: var(--accent-green);
}

.bool-badge.no {
  background: rgba(248, 81, 73, 0.15);
  color: var(--accent-red);
}

.score-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
}

.score-circle {
  width: 100px;
  height: 100px;
  border-radius: 50%;
  border: 4px solid var(--border-color);
  border-top-color: var(--score-color, var(--accent-blue));
  border-right-color: var(--score-color, var(--accent-blue));
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  margin: 8px 0;
  position: relative;
}

.score-value {
  font-size: 1.8rem;
  font-weight: 800;
  color: var(--score-color, var(--accent-blue));
  line-height: 1;
}

.score-label {
  font-size: 0.75rem;
  color: var(--text-muted);
}

.score-desc {
  font-size: 0.85rem;
  color: var(--text-secondary);
  margin-top: 8px;
}

.severity-bars {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.severity-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 4px 0;
}

.sev-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.85rem;
}

.severity-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.sev-count {
  font-weight: 700;
  font-size: 1rem;
  font-family: var(--font-mono);
}

.severity-summary {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid var(--border-color);
  font-size: 0.85rem;
  color: var(--text-secondary);
  text-align: center;
}
</style>
