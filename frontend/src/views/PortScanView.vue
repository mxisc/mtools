<template>
  <div class="portscan-view">
    <div class="view-header">
      <h1>端口扫描</h1>
      <p>高效的多线程端口扫描器，快速发现目标开放服务</p>
    </div>

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

    <div class="card scan-config">
      <div class="config-section">
        <h3 class="section-label">目标</h3>
        <div class="field-group">
          <label for="host">主机地址</label>
          <input
            id="host"
            v-model="form.host"
            type="text"
            placeholder="127.0.0.1 或 scanme.nmap.org"
            required
          />
        </div>
      </div>

      <div class="config-section">
        <h3 class="section-label">端口范围</h3>
        <div class="port-range">
          <div class="field-group">
            <label for="startPort">起始端口</label>
            <input
              id="startPort"
              v-model.number="form.startPort"
              type="number"
              min="1"
              max="65535"
              required
            />
          </div>
          <div class="range-separator">&ndash;</div>
          <div class="field-group">
            <label for="endPort">结束端口</label>
            <input
              id="endPort"
              v-model.number="form.endPort"
              type="number"
              min="1"
              max="65535"
              required
            />
          </div>
        </div>
      </div>

      <div class="config-section">
        <h3 class="section-label">扫描参数</h3>
        <div class="scan-params">
          <div class="field-group">
            <label for="workers">并发数</label>
            <input
              id="workers"
              v-model.number="form.workers"
              type="number"
              min="1"
              max="1000"
              required
            />
          </div>
          <div class="field-group">
            <label for="timeout">超时 (ms)</label>
            <input
              id="timeout"
              v-model.number="form.timeout"
              type="number"
              min="100"
              max="30000"
              required
            />
          </div>
          <div class="field-group">
            <label for="ipVersion">IP 版本</label>
            <select
              id="ipVersion"
              v-model="form.ipVersion"
              class="select-input"
            >
              <option value="ipv4">IPv4</option>
              <option value="ipv6">IPv6</option>
            </select>
          </div>
        </div>
      </div>

      <div class="config-actions">
        <button
          type="button"
          class="btn btn-primary btn-lg"
          :disabled="isScanning || !isValidHost"
          @click="startScan"
        >
          <span v-if="isScanning" class="spinner"></span>
          {{ isScanning ? '扫描中...' : '开始扫描' }}
        </button>
        <button
          v-if="isScanning"
          type="button"
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

    <div v-if="isScanning || progress" class="card progress-section mt-2">
      <div class="progress-header">
        <span class="progress-label">
          扫描进度: {{ scanned }} / {{ total }}
        </span>
        <span class="progress-percent">{{ progressPercent }}%</span>
      </div>
      <div class="progress-bar">
        <div class="progress-bar-fill" :style="{ width: progressPercent + '%' }"></div>
      </div>
      <div class="progress-stats">
        <span class="stat">已发现: <strong>{{ openPortsCount }}</strong> 个开放端口</span>
        <span v-if="lastOpenPort" class="stat last-port">
          最新: <code class="mono">{{ lastOpenPort.port }}</code>
        </span>
      </div>
    </div>

    <template v-if="scanResult">
      <div class="card results-section mt-2">
        <div class="results-header">
          <h3 class="section-title">扫描结果</h3>
          <div class="results-summary">
            主机: <code class="mono">{{ scanResult.host }}</code>
            &nbsp;|&nbsp;
            开放端口: <strong>{{ scanResult.openPorts.length }}</strong>
            &nbsp;|&nbsp;
            已扫描: <strong>{{ scanResult.scanned }}</strong> / {{ scanResult.total }}
          </div>
        </div>

        <div v-if="scanResult.openPorts.length === 0" class="empty-state">
          <div class="icon">&#x1F513;</div>
          <p>未发现开放端口</p>
          <p class="sub">指定范围内所有端口均处于关闭状态</p>
        </div>

        <div v-else class="table-container">
          <table class="ports-table">
            <thead>
              <tr>
                <th>#</th>
                <th>端口</th>
                <th>服务</th>
                <th>响应时间</th>
                <th>状态</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(port, index) in scanResult.openPorts"
                :key="index"
              >
                <td>{{ index + 1 }}</td>
                <td class="mono font-bold">{{ port.port }}</td>
                <td class="mono">{{ port.service || guessService(port.port) }}</td>
                <td class="mono">{{ formatDuration(port.durationMs) }}</td>
                <td>
                  <span class="badge badge-covered">开放</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <div v-else-if="!isScanning && !scanResult" class="empty-state mt-3">
      <div class="icon">&#x1F50D;</div>
      <p>请输入目标主机和端口范围开始扫描</p>
      <p class="sub">支持 IP 地址和域名，可自定义端口范围和并发参数</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import type { PortScanProgress as PSProgress, PortScanResult, OpenPortItem } from '@/types/models'
import { runPortScan, stopTask, onPortScanProgress, offPortScanProgress, isWailsAvailable } from '@/api/wails'
import { guessService, formatDuration } from '@/utils/helpers'

interface ScanForm {
  host: string
  startPort: number
  endPort: number
  workers: number
  timeout: number
  ipVersion: 'ipv4' | 'ipv6'
}

const wailsAvailable = ref(false)

onMounted(() => {
  wailsAvailable.value = isWailsAvailable()
  onPortScanProgress(progressHandler)
})

onUnmounted(() => {
  offPortScanProgress()
})

const form = ref<ScanForm>({
  host: '127.0.0.1',
  startPort: 1,
  endPort: 1024,
  workers: 100,
  timeout: 1000,
  ipVersion: 'ipv4',
})

const isScanning = ref(false)
const error = ref('')
const scanResult = ref<PortScanResult | null>(null)
const progress = ref<PSProgress | null>(null)
const liveOpenPorts = ref<OpenPortItem[]>([])

const isValidHost = computed(() => {
  return form.value.host.trim().length > 0
})

const scanned = computed(() => progress.value?.checkedCount || 0)
const total = computed(() => progress.value?.total || 0)
const progressPercent = computed(() => {
  if (!progress.value || total.value === 0) return 0
  return Math.round((scanned.value / total.value) * 100)
})
const openPortsCount = computed(() => liveOpenPorts.value.length)
const lastOpenPort = computed(() => {
  if (liveOpenPorts.value.length === 0) return null
  return liveOpenPorts.value[liveOpenPorts.value.length - 1]
})

const progressHandler = (data: any) => {
  const p = data as PSProgress
  progress.value = p
  if (p.openPort && p.openPort > 0) {
    const exists = liveOpenPorts.value.find(item => item.port === p.openPort)
    if (!exists) {
      liveOpenPorts.value.push({
        port: p.openPort,
        durationMs: 0,
        service: guessService(p.openPort),
      })
    }
  }
}

onMounted(() => {
  onPortScanProgress(progressHandler)
})

async function startScan() {
  if (isScanning.value || !isValidHost.value) return

  isScanning.value = true
  error.value = ''
  scanResult.value = null
  progress.value = null
  liveOpenPorts.value = []

  try {
    const data = await runPortScan(
      form.value.host,
      form.value.startPort,
      form.value.endPort,
      form.value.workers,
      form.value.timeout,
      form.value.ipVersion
    )

    scanResult.value = data as PortScanResult
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    error.value = `扫描失败: ${msg}`
  } finally {
    isScanning.value = false
  }
}

async function handleStop() {
  try {
    await stopTask()
  } catch {
  }
  isScanning.value = false
}
</script>

<style scoped>
.portscan-view {
  max-width: 1000px;
  margin: 0 auto;
}

.view-header {
  margin-bottom: 24px;
}

.view-header h1 {
  font-size: 1.5rem;
  font-weight: 800;
  margin-bottom: 6px;
}

.view-header p {
  color: var(--text-secondary);
  font-size: 0.95rem;
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

.scan-config {
  padding: 24px;
  display: grid;
  grid-template-columns: 1fr 1fr 1fr;
  gap: 24px;
  align-items: end;
}

.config-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.section-label {
  font-size: 0.8rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--accent-blue);
  margin: 0;
}

.field-group {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.field-group label {
  font-size: 0.8rem;
  font-weight: 600;
  color: var(--text-secondary);
}

.port-range {
  display: flex;
  align-items: flex-end;
  gap: 12px;
}

.port-range .field-group {
  flex: 1;
}

.range-separator {
  font-size: 1.2rem;
  font-weight: 700;
  color: var(--text-secondary);
  padding-bottom: 8px;
}

.scan-params {
  display: flex;
  gap: 12px;
}

.scan-params .field-group {
  flex: 1;
}

.select-input {
  padding: 10px 14px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: var(--radius-sm);
  background: rgba(255, 255, 255, 0.05);
  color: var(--text-primary);
  font-size: 0.95rem;
  font-weight: 500;
  transition: border-color 0.2s, box-shadow 0.2s;
  cursor: pointer;
  outline: none;
}

.select-input:focus {
  border-color: var(--accent-blue);
  box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.15);
}

.select-input option {
  background: var(--bg-card);
  color: var(--text-primary);
  padding: 8px;
}

.config-actions {
  display: flex;
  gap: 10px;
  align-items: flex-end;
  padding-bottom: 4px;
}

@media (max-width: 768px) {
  .scan-config {
    grid-template-columns: 1fr;
    gap: 20px;
  }
}

.error-banner {
  background: rgba(248, 81, 73, 0.1);
  border: 1px solid rgba(248, 81, 73, 0.3);
  color: var(--accent-red);
  padding: 12px 16px;
  border-radius: var(--radius-sm);
  font-size: 0.9rem;
}

.progress-section {
  padding: 20px;
}

.progress-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 10px;
}

.progress-label {
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.progress-percent {
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: 1.1rem;
  color: var(--accent-blue);
}

.progress-stats {
  display: flex;
  gap: 20px;
  margin-top: 10px;
  font-size: 0.85rem;
  color: var(--text-secondary);
}

.progress-stats .stat strong {
  color: var(--text-primary);
}

.progress-stats .last-port code {
  color: var(--accent-green);
  background: rgba(63, 185, 80, 0.1);
  padding: 1px 6px;
  border-radius: 3px;
}

.results-section {
  padding: 20px;
}

.results-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}

.results-summary {
  font-size: 0.9rem;
  color: var(--text-secondary);
}

.results-summary code {
  background: var(--bg-tertiary);
  padding: 2px 6px;
  border-radius: 3px;
  color: var(--accent-cyan);
}

.ports-table .mono {
  font-family: var(--font-mono);
}
</style>
