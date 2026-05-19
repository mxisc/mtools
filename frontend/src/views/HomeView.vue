<template>
  <div class="home-view">
    <div class="hero">
      <h1>&#x1F6E1;&#xFE0F; PortDesk 安全工具集</h1>
      <p>集成化的 Web 安全检查与端口扫描工具，帮助安全人员快速评估目标风险。</p>
    </div>

    <div class="tool-grid">
      <div class="tool-card" @click="navigateTo('/webcheck')">
        <div class="tool-icon webcheck">&#x1F512;</div>
        <h2>Web 安全检查</h2>
        <p>自动检测目标网站的安全配置，包括 HTTP 安全头、TLS/SSL 配置、HTTP 方法、DVWA 覆盖等。</p>
        <ul class="tool-features">
          <li>HTTP 安全头检测</li>
          <li>TLS/SSL 版本验证</li>
          <li>危险 HTTP 方法识别</li>
          <li>DVWA 模块覆盖分析</li>
        </ul>
        <button class="btn btn-primary btn-lg">启动检查</button>
      </div>

      <div class="tool-card" @click="navigateTo('/portscan')">
        <div class="tool-icon portscan">&#x1F50D;</div>
        <h2>端口扫描</h2>
        <p>高效的多线程端口扫描器，支持自定义端口范围和并发参数，快速发现目标开放服务。</p>
        <ul class="tool-features">
          <li>自定义端口范围</li>
          <li>多线程并发扫描</li>
          <li>服务自动识别</li>
          <li>实时进度反馈</li>
        </ul>
        <button class="btn btn-primary btn-lg">开始扫描</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()

function navigateTo(path: string) {
  router.push(path)
}
</script>

<style scoped>
.home-view {
  max-width: 960px;
  margin: 0 auto;
}

.hero {
  text-align: center;
  margin-bottom: 48px;
}

.hero h1 {
  font-size: 2rem;
  font-weight: 800;
  margin-bottom: 12px;
  background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.hero p {
  font-size: 1.05rem;
  color: var(--text-secondary);
  max-width: 600px;
  margin: 0 auto;
}

.tool-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 24px;
}

.tool-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius-lg);
  padding: 32px;
  cursor: pointer;
  transition: all var(--transition-normal);
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
}

.tool-card:hover {
  border-color: var(--accent-blue);
  box-shadow: var(--shadow-lg);
  transform: translateY(-4px);
}

.tool-icon {
  width: 72px;
  height: 72px;
  border-radius: var(--radius-md);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2rem;
  margin-bottom: 20px;
}

.tool-icon.webcheck {
  background: linear-gradient(135deg, rgba(88, 166, 255, 0.2), rgba(188, 140, 255, 0.2));
}

.tool-icon.portscan {
  background: linear-gradient(135deg, rgba(57, 210, 192, 0.2), rgba(88, 166, 255, 0.2));
}

.tool-card h2 {
  font-size: 1.3rem;
  font-weight: 700;
  margin-bottom: 10px;
  color: var(--text-primary);
}

.tool-card > p {
  color: var(--text-secondary);
  margin-bottom: 20px;
  line-height: 1.6;
}

.tool-features {
  list-style: none;
  text-align: left;
  width: 100%;
  margin-bottom: 24px;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 6px;
}

.tool-features li {
  padding: 4px 0;
  color: var(--text-secondary);
  font-size: 0.9rem;
  display: flex;
  align-items: center;
  gap: 8px;
}

.tool-features li::before {
  content: '';
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--accent-blue);
  flex-shrink: 0;
}
</style>
