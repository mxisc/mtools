# PortDesk

跨平台桌面网络安全工具集，使用 Go + Wails + Vue 3 构建。

## 功能特性

- **端口扫描** — 多线程 TCP 端口扫描，支持自定义端口范围、并发数、超时配置，实时进度展示与服务标注
- **Web 安全检查** — 非侵入式网站安全配置巡检，涵盖 HTTPS/TLS、安全响应头、Cookie 属性、CORS、敏感文件暴露、DVWA 类目覆盖对齐等

## 快速开始

### 开发环境运行

```bash
# 1. 安装 Wails CLI
go install github.com/wailsapp/wails/v2/cmd/wails@latest

# 2. 安装前端依赖
cd frontend && npm install && cd ..

# 3. 开发模式（支持热重载）
wails dev
```

### 构建生产版本

```bash
wails build -platform darwin/universal
```

构建产物位于 `build/bin/PortDesk.app`（macOS）。

### 运行已构建的应用

```bash
open build/bin/PortDesk.app
```

## 技术栈

| 层       | 技术                  |
|----------|-----------------------|
| 后端     | Go 1.23+              |
| GUI 框架 | Wails v2              |
| 前端     | Vue 3 + TypeScript    |
| 构建工具 | Vite                  |

## 项目结构

```
.
├── main.go                  # Wails 应用入口
├── wails.json               # Wails 配置
├── frontend/                # Vue 3 前端
│   ├── src/
│   │   ├── views/           # 页面组件
│   │   ├── components/      # 可复用组件
│   │   ├── api/             # Wails 后端 API 调用
│   │   └── types/           # TypeScript 类型定义
│   └── ...
├── internal/
│   ├── wailsapp/            # Wails Go 后端（绑定到前端）
│   ├── scanner/             # 端口扫描核心逻辑
│   └── webcheck/            # Web 安全检查核心逻辑
└── docs/
    └── LLM_PROJECT_BRIEF.md # 面向 AI 的项目上下文文档
```

## 架构说明

项目采用前后端分离架构：

- **Go 后端**：通过 Wails 绑定将 `RunPortScan`、`RunWebCheck` 等方法暴露给前端
- **Vue 前端**：通过 `window.go` 调用 Go 方法，通过 `window.runtime.EventsOn` 接收实时进度事件
- **核心逻辑**：`scanner` 和 `webcheck` 包完全独立于 UI，可复用于 CLI 或其他场景

## 下一步

- 结果导出（CSV/JSON）
- 服务指纹识别
- 子网扫描
- 扫描历史与配置持久化

## License

MIT
