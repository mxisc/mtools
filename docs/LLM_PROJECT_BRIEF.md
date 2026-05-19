# LLM Project Context

本文件只面向大模型，用于快速接手、续做、复盘，不面向普通用户。

## TL;DR

```yaml
project_name: PortDesk
language: Go
app_type: cross-platform desktop app
gui_framework: wails
ui_framework: vue3 + typescript + vite
ui_principles:
  - beautiful and polished interface
  - launcher plus independent tools
  - avoid stacking all tools in one page
  - dark theme with modern design
current_scope:
  - multi-thread TCP port scanning
  - website security checks
  - multi-module website security audit
  - real-time status updates via wails events
  - dashboard with security score
  - category-based findings browser
  - detail panel per finding
  - DVWA coverage alignment view
entrypoint: main.go
core_packages:
  - internal/wailsapp
  - internal/scanner
  - internal/webcheck
  - frontend/src/
primary_extension_direction:
  - export results
  - add tests
  - add service detection
  - add subnet scanning
```

## 项目目标

- 使用 `Go` 实现跨平台桌面网络工具
- 使用 `Wails` 提供现代化 Web 技术 GUI（替代 Fyne）
- 当前目标：稳定运行端口扫描 + Web 安全检查两大工具
- 后续可继续演进为更完整的安全/运维辅助工具

## 技术决策

- 语言：`Go`
- GUI：`Wails v2`（替代 Fyne）
- 前端：`Vue 3` + `TypeScript` + `Vite`
- 架构：`入口页 + 独立工具页`
- 分层：`UI`、`scanner`、`webcheck`、`wailsapp` 解耦

原因：

- Go 适合高并发扫描与跨平台构建
- Wails 提供原生 WebView 渲染，UI 美观度远优于 Fyne
- Vue 3 生态成熟，组件复用和样式定制灵活
- 解耦后核心逻辑可在未来复用至 CLI、API 或其他前端
- 入口页 + 工具页适合后续增加更多工具

## 文件地图

### `main.go`

- Wails 应用入口
- 使用 `//go:embed` 嵌入前端构建产物
- 绑定 `wailsapp.App` 到前端

### `wails.json`

- Wails 项目配置
- 定义前端构建命令、输出文件名、应用信息

### `frontend/`

- Vue 3 + TypeScript 前端项目
- 使用 Vite 构建

#### `frontend/src/views/`

- `HomeView.vue` — 工具入口首页
- `PortScanView.vue` — 端口扫描工具界面
- `WebCheckView.vue` — Web 安全检查工具界面

#### `frontend/src/components/`

- `webcheck/DashboardPanel.vue` — 安全评分仪表盘
- `webcheck/CategoryList.vue` — 检查分类列表
- `webcheck/DetailPanel.vue` — 发现详情面板

#### `frontend/src/api/wails.ts`

- Wails Go 方法调用封装
- Wails Events 进度订阅封装

#### `frontend/src/types/models.ts`

- TypeScript 类型定义（Finding、CoverageItem、PortScanResult 等）

#### `frontend/src/utils/helpers.ts`

- 工具函数：严重度标签映射、服务名称猜测、耗时格式化

### `internal/wailsapp/app.go`

- Wails Go 后端
- 绑定到前端的方法：`GetAppName`、`IsRunning`、`StopTask`、`RunWebCheck`、`RunPortScan`
- 通过 `runtime.EventsEmit` 推送扫描进度到前端
- 定义所有返回前端的 JSON 数据结构

### `internal/scanner/scanner.go`

- 定义扫描相关数据结构（`ScanOptions`、`OpenPort`、`Progress`）
- 参数校验
- 主机解析校验
- 基于 worker pool 的端口并发扫描
- 通过回调把进度推回调用方（Wails 层包装为 EventsEmit）
- 汇总并排序开放端口

### `internal/webcheck/checker.go`

- 网站安全检测核心
- 负责 URL 标准化、HTTP 请求、HTTPS/TLS 检查
- 负责安全响应头、Cookie 安全属性、CORS、HTTP 方法、页面与前端面、身份与权限面、接口与业务面、公开文件、敏感暴露、基础设施与供应链的检查
- 负责生成 DVWA 类目对齐覆盖矩阵，标注"已启发式检查"与"需人工复测"
- 输出结构化检测报告（`Report`、`Finding`、`CoverageItem`）

## 数据结构约定

### `scanner.ScanOptions`

- `Host`: 目标主机
- `StartPort`: 起始端口
- `EndPort`: 结束端口
- `Workers`: 并发 worker 数
- `Timeout`: 单端口超时时间

### `scanner.OpenPort`

- `Port`: 端口号
- `Duration`: 建连耗时

### `scanner.Progress`

- `CheckedPort`: 最近完成探测的端口
- `CheckedCount`: 已处理端口总数
- `Total`: 总端口数
- `Open`: 若当前端口开放，则附带 `OpenPort`

### `wailsapp.PortScanResult`

- `OpenPorts`: 开放端口列表（含服务标注）
- `Total`: 总扫描端口数
- `Scanned`: 实际扫描端口数
- `Host`: 目标主机

### `wailsapp.WebCheckResult`

- `CheckedAt`: 检测时间
- `Target`: 目标地址
- `FinalURL`: 最终 URL
- `StatusCode`: HTTP 状态码
- `UsesHTTPS`: 是否使用 HTTPS
- `TLSVersion`: TLS 版本
- `SupportedMethods`: 支持的 HTTP 方法
- `Findings`: 安全发现列表
- `DVWACoverage`: DVWA 覆盖矩阵

## Wails 通信模型

- 前端通过 `window.go.main.App.*` 调用 Go 方法
- Go 方法返回结构化对象（Wails 自动 JSON 序列化/反序列化）
- Go 通过 `runtime.EventsEmit(ctx, eventName, data)` 推送实时事件
- 前端通过 `window.runtime.EventsOn(eventName, callback)` 订阅事件
- `RunPortScan` 扫描过程中持续推送 `portscan:progress` 事件

## 执行流程

### 端口扫描

1. 前端读取用户输入（主机、端口范围、并发、超时）
2. 调用 `RunPortScan()`
3. Go 层创建 context + 调用 `scanner.Scan()`
4. `scanner.Scan()` 创建 job channel 与 worker pool
5. worker 使用 `net.DialTimeout("tcp", ...)` 探测端口
6. 聚合循环串行消费 worker 结果
7. 每完成一个端口，通过 `EventsEmit` 推送到前端
8. 前端接收 `portscan:progress` 事件，更新进度条和开放端口列表

### Web 安全检查

1. 前端读取目标 URL
2. 调用 `RunWebCheck()`
3. Go 层调用 `webcheck.Check()`
4. 执行完整的检测矩阵（传输层、安全头、Cookie、CORS、方法、敏感暴露等）
5. 返回结构化 `WebCheckResult`
6. 前端展示仪表盘、分类列表、详情面板

## 并发模型

- 端口扫描：一个 goroutine 投递任务到 jobs channel，多个 worker 消费，聚合循环串行消费结果
- Web 检查：同步执行，检测逻辑内部按模块串行/并发混合
- 所有扫描任务通过 `context.Context` 支持取消
- `App` 结构体使用 `sync.Mutex` 保护 `running` 状态，确保同一时间只有一个任务

## 当前已实现功能

- 入口页与工具导航（Vue Router）
- 端口扫描（多线程 + 实时进度 + 服务标注）
- 网站安全基础检测（多模块审计）
- 安全评分计算与可视化
- 按严重度和分类浏览发现
- DVWA 类目对齐覆盖视图
- 反射输入与开放重定向低风险主动探针
- 敏感文件、依赖清单、日志、调试端点暴露检查
- 页面前端面、认证面、业务参数面启发式检查
- 手动停止扫描/检测

## 当前限制

- 只支持 TCP
- 只支持单主机
- 没有导出功能
- 没有历史记录
- 没有服务指纹识别（仅常见端口映射）
- 没有自动化测试
- 网站安全工具偏向"自有站点安全巡检"，不能单独证明站点绝对安全
- 当前未覆盖需要登录态、业务流、权限链、复杂逻辑漏洞的深度验证
- 对齐 DVWA 的部分能力属于"启发式覆盖 + 人工复测提示"，不是直接利用型验证

## 修改时的硬约束

- 不要把网络扫描逻辑塞进前端或 `wailsapp`
- 不要把所有工具堆在同一个页面
- 新工具默认走"入口页 -> 独立工具页"的形式
- 界面要保持美观，优先保证层次清晰、分区明确、组件一致
- 优先保持 `scanner.ScanOptions` 与 `scanner.Scan` 的接口清晰
- 优先保持 `webcheck.Check` 的接口清晰
- 如需新增扫描类型，先考虑在 `internal/scanner` 内扩展
- 如需新增网站检测能力，先考虑在 `internal/webcheck` 内扩展
- Go 后端类型和前端 TypeScript 类型必须保持一致
- 不要让前端直接访问网络，所有请求必须经过 Go 后端

## 接手顺序建议

1. 先读 `frontend/src/App.vue`（主框架）
2. 读 `frontend/src/router/index.ts`（路由结构）
3. 读目标页面 `frontend/src/views/PortScanView.vue` 或 `WebCheckView.vue`
4. 读 Go 后端 `internal/wailsapp/app.go`（绑定方法）
5. 读核心逻辑 `internal/scanner/scanner.go` 或 `internal/webcheck/checker.go`
6. 最后看 `main.go`

## 下一步优先级

1. 给 `scanner` 补单元测试
2. 增加结果导出为 `csv` 或 `json`
3. 增加更精确的服务指纹识别
4. 增加网段扫描
5. 做配置持久化

## 构建与运行

- 开发模式：`wails dev`
- 生产构建：`wails build -platform darwin/universal`
- 构建产物：`build/bin/PortDesk.app`
- 依赖同步：`cd frontend && npm install` / `go mod tidy`
- macOS 需已安装 Go 和 Node.js

## 经验沉淀模板

每次迭代后，按以下结构追加记录，便于后续大模型继续接手：

```markdown
## Iteration Summary

### Goal
- 本次目标

### Changes
- 改了哪些文件
- 改了哪些能力

### Decisions
- 为什么采用当前方案
- 放弃了哪些备选方案

### Risks
- 当前风险
- 可能回归点

### Next
- 下一步最值得做的 1-3 件事
```

## Fyne 到 Wails 迁移记录

### Goal
- 将 GUI 从 Fyne（纯 Go）迁移到 Wails + Vue 3（Web 技术栈），大幅提升界面美观度和可读性

### Changes
- 移除 `internal/ui/` 目录（所有 Fyne UI 代码）
- 移除 `go.mod` 中 Fyne 依赖
- 新增 `internal/wailsapp/app.go`（Wails Go 后端）
- 新增 `frontend/` 目录（Vue 3 + TypeScript 前端）
- 重写 `main.go`（Wails 入口 + 嵌入前端资源）
- 新增 `wails.json` 配置

### Decisions
- 选择 Wails 而非 Electron：更轻量、原生 WebView、Go 原生绑定
- 选择 Vue 3 而非 React：团队熟悉度 + Wails 官方模板支持
- 保留 `scanner` 和 `webcheck` 核心逻辑不变，仅替换 UI 层

### Risks
- Wails 需要 WebView2（Windows）/ WebKit（macOS/Linux）运行时
- 前端 TypeScript 类型必须与 Go 类型手动保持同步（无自动生成）

### Next
- 完善错误处理与用户提示
- 增加结果导出功能
- 补全单元测试
