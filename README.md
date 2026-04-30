# AnXin Security

一个基于 Tauri 2.0 的 Windows 安全防护桌面应用，提供实时文件扫描、ETW 行为监控和威胁防护功能。

A Windows security protection desktop application based on Tauri 2.0, providing real-time file scanning, ETW behavior monitoring, and threat protection.

## 主要功能 / Main Features

- **实时文件扫描**: 基于 Axon/Raven 双引擎签名数据库的安全扫描
- **ETW 行为监控**: 使用 ETW (Event Tracing for Windows) 实时监控进程行为
- **威胁防护**: 实时拦截和隔离恶意文件，支持进程挂起/恢复/终止
- **文件隔离区**: AES-128-GCM 加密隔离 + 安全擦除恢复
- **进程监控**: 监控系统进程活动和文件操作
- **启动项管理**: 启动允许列表 + 排除项管理

## 技术架构 / Tech Stack

| 层级 | 技术 |
|------|------|
| **前端** | React 18 + TypeScript + Vite + Zustand + Framer Motion |
| **后端** | Rust (Tauri 2.0) + Tokio 异步运行时 |
| **原生模块** | C++ DLL (ETW Bridge, Process Watcher, File Hook via Detours) |
| **安全引擎** | Axon / Raven 扫描引擎 DLL |
| **数据库** | SQLite (sqlx ORM) |
| **加密** | AES-128-GCM + SHA-256 |
| **构建** | Vite + Tauri CLI + NSIS 安装包 |

## 项目结构 / Project Structure

```
AnXinSecurity/
├── src/                         # React 前端
│   ├── main.tsx                 # React 入口
│   ├── App.tsx                  # 根组件（标题栏 + 侧边栏 + 页面路由 + 弹窗集成）
│   ├── api/                     # Tauri invoke 封装层
│   │   ├── scanner.ts           # 扫描引擎 API
│   │   ├── behavior.ts          # ETW 行为事件 API
│   │   ├── quarantine.ts        # 隔离区 API
│   │   ├── config.ts            # 配置管理 API
│   │   ├── exclusions.ts        # 排除项 API
│   │   └── allowlist.ts         # 启动允许列表 API
│   ├── stores/                  # Zustand 状态管理
│   │   ├── configStore.ts       # 全局配置 + 页面路由
│   │   ├── scannerStore.ts      # 扫描状态
│   │   ├── quarantineStore.ts   # 隔离区状态
│   │   ├── themeStore.ts        # 主题与动画状态
│   │   └── toastStore.ts        # 全局通知状态
│   ├── components/              # React 组件
│   │   ├── TitleBar.tsx         # 自定义窗口标题栏
│   │   ├── Sidebar.tsx          # 侧边栏导航
│   │   ├── OverviewPage.tsx     # 概览页
│   │   ├── ScanPage.tsx         # 文件扫描页
│   │   ├── QuarantinePage.tsx   # 隔离区管理页
│   │   ├── BehaviorPage.tsx     # 行为分析页
│   │   ├── SettingsPage.tsx     # 设置页
│   │   ├── InterceptionModal.tsx # 进程拦截弹窗
│   │   ├── TrayExitPrompt.tsx   # 托盘退出确认弹窗
│   │   ├── Toast.tsx            # 全局通知组件
│   │   └── ErrorBoundary.tsx    # 错误边界组件
│   └── styles/global.css        # Fluent 2 设计系统样式
├── src-tauri/                   # Rust 后端
│   ├── src/
│   │   ├── main.rs              # Tauri Builder + 服务初始化
│   │   ├── lib.rs               # 模块导出
│   │   ├── commands/            # 31 个 Tauri Commands
│   │   ├── services/            # 8 个核心服务
│   │   ├── ffi/                 # FFI 绑定层 (libloading)
│   │   ├── models/              # 数据模型
│   │   └── utils/               # 工具函数（加密、路径、缓存、过滤）
│   ├── Cargo.toml               # Rust 依赖清单
│   └── tauri.conf.json          # Tauri 应用配置
├── native/                      # C++ 原生模块
│   ├── etw_bridge/              # ETW 监控桥接 DLL
│   ├── process_watcher/         # 进程监控 DLL
│   ├── file_hook/               # 文件钩子 (Detours 4.0.1, MIT)
│   ├── raven_engine/            # Raven 扫描引擎
│   └── trust_bridge/            # 可信证书桥接
├── Engine/                      # 已编译扫描引擎
│   ├── Axon/                    # Axon 引擎 DLL
│   └── Raven/                   # Raven 引擎 DLL
├── config/                      # 运行时配置
│   ├── app.json                 # 主应用配置
│   ├── etw_match_rules.json     # ETW 匹配规则
│   ├── scan_rules.json          # 扫描规则
│   └── i18n/                    # 国际化
├── data/                        # 运行时数据
│   ├── anxin_signature_db.bin   # 签名数据库
│   ├── behavior/                # 行为日志 SQLite
│   └── logs/                    # 日志
└── archive/                     # 已归档的旧版 Electron 代码
    └── electron-legacy/
```

## 安装和使用 / Installation

### 环境要求 / Requirements

- **Node.js** >= 18
- **Rust 工具链** (rustc >= 1.95, cargo >= 1.95)
- **Windows 10/11** 操作系统
- **Visual Studio 2019+ Build Tools** (C++ 开发工作负载)
- **WebView2** (Windows 10/11 已内置)

### 开发环境搭建 / Dev Setup

1. 克隆项目
```bash
git clone <repository-url>
cd AnXinSecurity
```

2. 安装依赖
```bash
npm install
```

3. 启动开发模式
```bash
npm run dev
```

首次启动将：
1. 启动 Vite 开发服务器（端口 1421）
2. 编译 Rust 后端（首次约 5-10 分钟）
3. 打开 Tauri 应用窗口

### 生产构建 / Production Build

```bash
npm run build
```

生成的 NSIS 安装包位于: `src-tauri/target/release/bundle/nsis/AnXinSecurity_1.0.0_x64-setup.exe`

### 可用命令 / Available Commands

| 命令 | 说明 |
|------|------|
| `npm run dev` | 启动完整开发模式（前端 + Tauri） |
| `npm run dev:frontend` | 仅启动前端开发服务器 |
| `npm run build` | 构建生产版本（前端 + 安装包） |
| `npm run build:frontend` | 仅构建前端 |
| `npm run storybook` | 启动 Storybook 组件开发 |
| `npm run lint` | 代码语法检查 |

## 快速问题排查 / Troubleshooting

### 编译卡在 "Updating crates.io index"
配置 Cargo 国内镜像源 (`~/.cargo/config.toml`):
```toml
[source.crates-io]
replace-with = 'tuna'
[source.tuna]
registry = "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/"
[http]
check-revoke = false
```

### 端口 1421 被占用
```bash
netstat -ano | findstr :1421
taskkill /F /PID <PID>
```

### DLL not found 错误
1. 检查 `native/bin/win32-x64/` 目录是否存在
2. 确保 DLL 未被杀毒软件隔离
3. 以管理员身份运行应用

### Rust 编译错误
```bash
cd src-tauri
cargo clean
cargo build
```

## 架构说明 / Architecture

### 前后端通信

- **Tauri Commands**: 前端通过 `invoke()` 调用 Rust 后端暴露的 31 个命令
- **Tauri Events**: Rust 后端通过 Events 向前端推送实时事件（`etw-event`、`scan-progress`、`quarantine-updated`、`process-intercepted`、`tray-exit-requested`）

### Rust 后端分层

| 层 | 目录 | 职责 |
|---|------|------|
| 接口层 | `commands/` | 31 个 `#[tauri::command]`，透传到服务层 |
| 应用层 | `services/` | ETW 服务、引擎通信、行为分析、隔离区、托盘 |
| 领域层 | `models/` | AppConfig、EtwEvent、ScanResult 等数据模型 |
| 基础设施层 | `ffi/` `utils/` | DLL 动态加载、加密、路径处理、PID 缓存 |

### 安全注意事项 / Security Notes

- **加密密钥**: 当前使用固定密钥用于开发/演示，**生产环境必须使用 Windows DPAPI** 或硬件安全模块管理密钥
- **安全擦除**: 隔离文件删除执行三次覆写（随机数据 → 0x00 → 0xFF），符合 NIST SP 800-88 建议
- **受保护进程**: 关键系统进程（csrss.exe、smss.exe、wininit.exe 等）禁止操作
- **自身保护**: 拒绝操作自身进程

## 开源组件与协议 / Open Source Components

### 运行时依赖

| 组件 | 许可证 |
|------|--------|
| react, react-dom | MIT |
| zustand | MIT |
| framer-motion | MIT |
| lucide-react | ISC |
| @tauri-apps/api | MIT / Apache-2.0 |

### 开发依赖

| 组件 | 许可证 |
|------|--------|
| @tauri-apps/cli | MIT / Apache-2.0 |
| vite | MIT |
| typescript | Apache-2.0 |
| storybook | MIT |

### 仓库内第三方代码

| 组件 | 许可证 |
|------|--------|
| Microsoft Research Detours 4.0.1 | MIT (`native/file_hook/src/Detours`) |
| pico.min.css | MIT (`assets/ui/pico.min.css`) |

## 许可证 / License

本项目基于 MIT 许可证开源，具体参见各组件对应的许可证文件。

This project is open source under the MIT License. See individual components for their respective licenses.
