<template>
  <div class="app-container">
    <nav class="navbar">
      <div class="navbar-brand" @click="$router.push('/')">
        <div class="logo">P</div>
        <span>PortDesk</span>
      </div>
      <div class="navbar-nav">
        <button
          class="nav-link"
          :class="{ active: $route.name === 'home' }"
          @click="$router.push('/')"
        >
          <span class="icon">&#x1F3E0;</span>
          首页
        </button>
        <button
          class="nav-link"
          :class="{ active: $route.name === 'webcheck' }"
          @click="$router.push('/webcheck')"
        >
          <span class="icon">&#x1F512;</span>
          Web 安全检查
        </button>
        <button
          class="nav-link"
          :class="{ active: $route.name === 'portscan' }"
          @click="$router.push('/portscan')"
        >
          <span class="icon">&#x1F50D;</span>
          端口扫描
        </button>
      </div>
      <div class="navbar-status">
        <div class="status-dot" :class="{ running: isTaskRunning }"></div>
        <span>{{ isTaskRunning ? '运行中' : '空闲' }}</span>
      </div>
    </nav>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { isRunning, onPortScanProgress, offPortScanProgress } from '@/api/wails'

const isTaskRunning = ref(false)
const route = useRoute()

onMounted(async () => {
  isTaskRunning.value = await isRunning()
  onPortScanProgress(() => {
    isTaskRunning.value = true
  })
})

onUnmounted(() => {
  offPortScanProgress()
})

watch(() => route.fullPath, async () => {
  const status = await isRunning()
  if (!status) {
    isTaskRunning.value = false
  }
})
</script>
