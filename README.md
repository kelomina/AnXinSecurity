# AnXin Security

<div align="center">

![Rust](https://img.shields.io/badge/Rust-1.95+-orange?logo=rust&style=flat-square)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-blue?logo=typescript&style=flat-square)
![Tauri](https://img.shields.io/badge/Tauri-2.0-purple?logo=tauri&style=flat-square)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&style=flat-square)

一个基于 Tauri 2.0 的 Windows 安全防护桌面应用，提供实时文件扫描、ETW 行为监控和威胁防护功能。

A Windows security protection desktop application based on Tauri 2.0, providing real-time file scanning, ETW behavior monitoring, and threat protection.

</div>

---

<details>
<summary><b>目录 / Table of Contents</b></summary>

- [主要功能 / Main Features](#主要功能--main-features)
- [Fluent 2 设计系统 / Fluent 2 Design System](#fluent-2-设计系统--fluent-2-design-system)
- [技术架构 / Tech Stack](#技术架构--tech-stack)
- [项目结构 / Project Structure](#项目结构--project-structure)
- [配置文件职责 / Configuration File Responsibilities](#配置文件职责--configuration-file-responsibilities)
- [安装和使用 / Installation](#安装和使用--installation)
- [可用命令 / Available Commands](#可用命令--available-commands)
- [快速问题排查 / Troubleshooting](#快速问题排查--troubleshooting)
- [架构说明 / Architecture](#架构说明--architecture)
- [开源组件与协议 / Open Source Components](#开源组件与协议--open-source-components)
- [许可证 / License](#许可证--license)

</details>

---

## 主要功能 / Main Features

- **实时文件扫描** — 基于 Axon/Raven 双引擎签名数据库的安全扫描，支持文件和进程内存扫描
- **ETW 行为监控** — 使用 ETW (Event Tracing for Windows) 实时监控进程行为，支持可配置匹配规则
- **威胁防护** — 实时拦截和隔离恶意文件，支持进程挂起/恢复/终止，提供用户决策弹窗
- **文件隔离区** — AES-128-GCM 加密隔离 + NIST SP 800-88 安全擦除恢复
- **进程监控** — 监控系统进程活动和文件操作（创建、修改、删除）
- **启动快照扫描** — 系统启动时自动扫描运行中进程，快速检测威胁
- **行为生命周期追踪** — 查看单个进程的详细行为时间线
- **风险分析引擎** — 基于多维度特征的风险分级评估
- **ML 机器学习训练** — 集成 LightGBM 模型训练管道
- **信任项目管理** — 在设置页统一管理启动允许与扫描/监控排除；DPAPI 加密存储运行时数据
- **文件系统监控** — 实时监控文件创建和修改事件
- **中英双语国际化** — 支持中文和英文界面切换，可扩展更多语言

---

## Fluent 2 设计系统 / Fluent 2 Design System

项目采用自定义实现的 Fluent 2 设计规范，通过 CSS 变量体系实现完整的设计 Token 管理：

| Token 类别 | 说明 | 值 / 示例 |
|------------|------|-----------|
| **品牌色** | 主色调配套 fill/stroke 系列变量 | `#4CA2FF` / `--fill-accent` |
| **阴影系统** | 5 级阴影 Token | `--shadow-tooltip` → `--shadow-window` |
| **焦点环** | 双层焦点环设计 | `--focus-ring-accent` + `--focus-ring-high-contrast` |
| **圆角规范** | 三级圆角体系 | small 4px / medium 6px / large 8px |
| **材质效果** | Windows 11 Mica/Acrylic 毛玻璃 | `backdrop-filter: blur(40px) saturate(1.2)` |
| **动画时序** | hover/press/focus 动作 Token | 配合 Framer Motion 页面切换动画 |
| **双主题** | 深色/浅色主题 + 跟随系统 | `prefers-color-scheme` 媒体查询监听 |
| **无边框窗口** | 自定义 TitleBar 组件 | `tauri.conf.json` decorations: false |

### 扫描页威胁操作规范

- 主操作使用 filled danger button，次操作使用 outline accent button，图标与文字保持 8px 间距
- "清除威胁"和"添加信任"按钮仅在扫描结果中存在威胁时渲染
- 未选择威胁时保持 disabled 状态，避免误操作

---

## 技术架构 / Tech Stack

| 层级 | 技术 |
|------|------|
| **前端** | React 18 + TypeScript + Vite + Zustand + Framer Motion |
| **后端** | Rust (Tauri 2.0) + Tokio 异步运行时 |
| **原生模块** | C++ DLL (ETW Bridge, Process Watcher, File Hook via Detours) |
| **安全引擎** | Axon（Apache 2.0 开源，预编译 DLL）/ Raven 扫描引擎 DLL + 签名引擎 DLL |
| **数据库** | SQLite (sqlx ORM) |
| **加密** | AES-128-GCM + SHA-256 |
| **构建** | Vite + Tauri CLI + NSIS 安装包 |

---

## 项目结构 / Project Structure

```
AnXinSecurity/
├── src/                          # React 前端
│   ├── main.tsx                  # React 入口
│   ├── App.tsx                   # 根组件（标题栏 + 侧边栏 + 页面路由 + 弹窗集成）
│   ├── api/                      # Tauri invoke 封装层 — 15 个模块
│   │   ├── 扫描类    scanner.ts, scanRules.ts
│   │   ├── 进程类    process.ts
│   │   ├── 行为类    behavior.ts
│   │   ├── 配置类    config.ts, exclusions.ts, allowlist.ts, devSettings.ts
│   │   ├── 系统类    system.ts, fs.ts, i18n.ts, logs.ts
│   │   └── 工具类    quarantine.ts, training.ts, errorTrace.ts
│   ├── stores/                   # Zustand 状态管理 — 6 个 Store
│   │   ├── configStore.ts        # 全局配置 + 页面路由
│   │   ├── scannerStore.ts       # 扫描状态
│   │   ├── quarantineStore.ts    # 隔离区状态
│   │   ├── themeStore.ts         # 主题与动画状态
│   │   ├── i18nStore.ts          # 国际化状态
│   │   └── toastStore.ts         # 全局通知状态
│   ├── components/               # React 组件 — 13 个
│   │   ├── TitleBar.tsx          # 自定义窗口标题栏
│   │   ├── Sidebar.tsx           # 侧边栏导航
│   │   ├── OverviewPage.tsx      # 概览页
│   │   ├── ScanPage.tsx          # 文件扫描页
│   │   ├── QuarantinePage.tsx    # 隔离区管理页
│   │   ├── BehaviorPage.tsx      # 行为分析页
│   │   ├── BehaviorLifecyclePage.tsx  # 行为生命周期详情
│   │   ├── SettingsPage.tsx      # 设置页
│   │   ├── SplashScreen.tsx      # 启动画面
│   │   ├── InterceptionModal.tsx  # 进程拦截弹窗
│   │   ├── TrayExitPrompt.tsx    # 托盘退出确认弹窗
│   │   ├── Toast.tsx             # 全局通知组件
│   │   └── ErrorBoundary.tsx     # 错误边界组件
│   └── styles/global.css         # Fluent 2 设计系统样式
├── src-tauri/                    # Rust 后端（Tauri 2.0）
│   ├── src/
│   │   ├── main.rs               # Tauri Builder + 服务初始化
│   │   ├── lib.rs                # 模块导出
│   │   ├── commands/             # 24 个命令模块（57+ 个 Tauri 命令）
│   │   ├── services/             # 20 个业务服务
│   │   ├── models/               # 数据模型
│   │   └── utils/                # 工具函数（加密、路径、缓存、过滤）
│   ├── Cargo.toml                # Rust 依赖清单
│   └── tauri.conf.json           # Tauri 应用配置
├── native/                       # C++ 原生模块
│   ├── etw_bridge/               # ETW 监控桥接 DLL
│   ├── process_watcher/          # 进程监控 DLL
│   ├── file_hook/                # 文件钩子 (Detours 4.0.1, MIT)
│   ├── raven_engine/             # Raven 扫描引擎
│   └── trust_bridge/             # 可信证书桥接
├── Engine/                       # 已编译扫描引擎（gitignored，本地构建生成）
├── config/                       # 运行时配置
│   ├── app.json                  # 主应用配置
│   ├── etw_match_rules.json      # ETW 匹配规则
│   ├── scan_rules.json           # 扫描规则
│   └── i18n/                     # 国际化（zh-CN, en-US）
├── tests/                        # 前端测试（Node.js）
│   ├── unit/
│   ├── integration/
│   ├── mocks/
│   └── fixtures/
├── data/                         # 运行时数据（gitignored，首次运行自动生成）
├── build/                        # 构建输出与安装包辅助文件（gitignored，打包生成）
├── assets/                       # 静态资源
│   └── ui/pico.min.css           # 基础 CSS 重置
```

---

## 配置文件职责 / Configuration File Responsibilities

> `config/` 目录同时包含可提交的静态配置和运行时生成的本地状态文件。维护时应先区分用途，避免把运行时状态、缓存或派生文件当作产品默认配置提交。

<details>
<summary><b>点击展开 — 可提交的静态配置 / Tracked Static Config</b></summary>

| 文件 | 用途 | 主要读取方 | 维护注意事项 |
|------|------|------------|--------------|
| `config/app.json` | 主应用静态配置：品牌名、主题色、默认页面、托盘行为、窗口尺寸、扫描限制、引擎 IPC、行为/进程/文件监控开关、行为数据库路径。旧版 `exclusions` 与 `startupAllowlist` 字段仅用于兼容迁移，不再作为运行时写入目标。 | `src-tauri/src/models/config.rs`、`commands/config.rs`、`commands/i18n.rs`、`commands/dev_settings.rs`、前端 `configStore` | 不得写入真实密钥、真实令牌或生产敏感路径；设置页保存主配置时会剥离运行时列表字段，运行时用户状态应写入 APPDATA。 |
| `config/scan_rules.json` | 快速扫描/扫描规则配置，定义快速扫描目录、文件和是否包含运行中进程等扫描入口规则。 | `src-tauri/src/commands/scan_rules.rs`、前端 `scanRules.ts` | 只存放规则模板和安全默认值；不要放本机私有样本路径或用户隐私路径。 |
| `config/etw_match_rules.json` | ETW 行为匹配规则，定义 provider、operation、severity、threatType、recommendAction 和目标匹配条件。 | ETW 规则加载与行为检测链路 | 规则应可解释、可复现；新增规则需避免过宽匹配导致误拦截。 |
| `config/i18n/zh-CN.json` | 中文语言包。 | `src-tauri/src/commands/i18n.rs`、前端 `i18nStore` | 仅维护界面文本，不承载业务配置。 |
| `config/i18n/en-US.json` | 英文语言包。 | `src-tauri/src/commands/i18n.rs`、前端 `i18nStore` | 需与中文语言包键名保持同步。 |

</details>

<details>
<summary><b>点击展开 — 运行时生成文件 / Runtime Generated Files</b></summary>

| 文件 | 用途 | Git 策略 | 维护注意事项 |
|------|------|----------|--------------|
| `config/scan_cache.json` | 扫描判决缓存或本地扫描缓存数据。 | 已在 `.gitignore` 中忽略。 | 属于本机运行状态，不应提交。 |
| `config/quarantine_index.json` | 隔离区索引或兼容性运行时状态。 | 已在 `.gitignore` 中忽略。 | 可能包含本机文件路径，不应提交。 |
| `config/startup_allowlist.enc` | 加密后的启动允许列表派生文件。 | 已在 `.gitignore` 中忽略。 | 属于本机敏感运行数据，不应提交或写入 README 示例。 |
| `%APPDATA%/AnXinSecurity/runtime/startup_allowlist.json` | 启动允许列表运行时状态，替代旧版 `config/app.json` 中的 `startupAllowlist` 可变字段；文件内容使用 Windows DPAPI 加密并带完整性校验。 | 位于用户 APPDATA，不进入 git；缺少 APPDATA 时回退到已忽略的 `data/runtime/`。 | 设置页"信任项目"中的文件项会写入此文件，避免修改仓库内 `config/app.json` 触发 `npm run dev` 自动重载；旧明文 runtime 文件首次读取后会自动加密迁移。 |
| `%APPDATA%/AnXinSecurity/runtime/exclusions.json` | 扫描排除项运行时状态，替代旧版 `config/app.json` 中的 `exclusions` 可变字段；文件内容使用 Windows DPAPI 加密并带完整性校验。 | 位于用户 APPDATA，不进入 git；缺少 APPDATA 时回退到已忽略的 `data/runtime/`。 | 设置页"信任项目"会统一写入此文件，使扫描和实时监控跳过对应路径；旧明文 runtime 文件首次读取后会自动加密迁移。 |

</details>

新增配置项时优先放入 `config/app.json` 或对应的专用配置文件；若配置只服务于扫描规则、ETW 规则或语言文本，应放入对应文件，避免把不同职责混在一个文件中。

---

## 安装和使用 / Installation

### 环境要求 / Requirements

- **Node.js** >= 18
- **Rust 工具链** (rustc >= 1.95, cargo >= 1.95)
- **Windows 10/11** 操作系统
- **Visual Studio 2019+ Build Tools** (C++ 开发工作负载)
- **WebView2** (Windows 10/11 已内置)

### 开发环境搭建 / Dev Setup

```bash
# 1. 克隆项目
git clone <repository-url>
cd AnXinSecurity

# 2. 安装依赖
npm install

# 3. 启动开发模式
npm run dev
```

> **提示**: 首次启动将：
> 1. 启动 Vite 开发服务器（端口 1421）
> 2. 编译 Rust 后端（首次约 5-10 分钟）
> 3. 打开 Tauri 应用窗口

### 生产构建 / Production Build

```bash
npm run build
```

生成的 NSIS 安装包位于: `src-tauri/target/release/bundle/nsis/AnXinSecurity_1.0.0_x64-setup.exe`

---

## 可用命令 / Available Commands

| 命令 | 说明 |
|------|------|
| `npm run dev` | 启动完整开发模式（前端 + Tauri） |
| `npm run dev:frontend` | 仅启动前端开发服务器 |
| `npm run build` | 构建生产版本（前端 + 安装包） |
| `npm run build:frontend` | 仅构建前端 |
| `npm run test` | 运行 Node.js 测试 |
| `npm run typecheck` | TypeScript 类型检查 |
| `npm run lint` | ESLint 代码检查 |

---

## 快速问题排查 / Troubleshooting

<details>
<summary><b>编译卡在 "Updating crates.io index"</b></summary>

配置 Cargo 国内镜像源 (`~/.cargo/config.toml`):

```toml
[source.crates-io]
replace-with = 'tuna'
[source.tuna]
registry = "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/"
[http]
check-revoke = false
```

</details>

<details>
<summary><b>端口 1421 被占用</b></summary>

```bash
netstat -ano | findstr :1421
taskkill /F /PID <PID>
```

</details>

<details>
<summary><b>DLL not found 错误</b></summary>

1. 检查 `native/bin/win32-x64/` 目录是否存在
2. 确保 DLL 未被杀毒软件隔离
3. 以管理员身份运行应用

</details>

<details>
<summary><b>Rust 编译错误</b></summary>

```bash
cd src-tauri
cargo clean
cargo build
```

</details>

---

## 架构说明 / Architecture

### 前后端通信

- **Tauri Commands** — 前端通过 `invoke()` 调用 Rust 后端暴露的 57+ 个命令（分布在 24 个命令模块中）
- **Tauri Events** — Rust 后端通过 Events 向前端推送实时事件（`etw-event`、`scan-progress`、`quarantine-updated`、`process-intercepted`、`tray-exit-requested`）
- **前端 API 层** — 15 个 API 模块按功能分组封装 Tauri invoke 调用

### Rust 后端分层

| 层 | 目录 | 职责 |
|---|------|------|
| 接口层 | `commands/` | 24 个命令模块（57+ 个 `#[tauri::command]`），透传到服务层 |
| 应用层 | `services/` | 20 个业务服务，编排领域逻辑 |
| 领域层 | `models/` | AppConfig、EtwEvent、ScanResult 等数据模型 |
| 基础设施层 | `utils/` | 加密、路径处理、PID 缓存、过滤工具 |

### Rust 后端服务列表

| 分组 | 服务模块 |
|------|---------|
| **引擎/扫描** | `engine_service`, `native_engine_service`, `scan_result_cache_service` |
| **ETW/行为** | `etw_service`（含 etw/session, etw/rules, etw/parser）, `behavior_service` |
| **隔离/拦截/风险** | `quarantine_service`, `interception_service`, `risk_service` |
| **监控** | `process_monitor_service`, `process_scanner_service`, `file_monitor_service`, `hook_service`, `snapshot_service` |
| **信任/策略** | `trust_service`, `path_policy_service` |
| **训练/配置** | `training_service`, `runtime_list_store` |
| **系统/工具** | `tray_service` |

### 前端 15 个 API 模块分组

| 分组 | API 模块 |
|------|---------|
| **扫描** | `scanner.ts`, `scanRules.ts` |
| **进程** | `process.ts` |
| **行为** | `behavior.ts` |
| **配置** | `config.ts`, `exclusions.ts`, `allowlist.ts`, `devSettings.ts` |
| **系统** | `system.ts`, `fs.ts`, `i18n.ts`, `logs.ts` |
| **工具** | `quarantine.ts`, `training.ts`, `errorTrace.ts` |

### 安全注意事项 / Security Notes

- **加密密钥**: 当前使用固定密钥用于开发/演示，**生产环境必须使用 Windows DPAPI** 或硬件安全模块管理密钥
- **安全擦除**: 隔离文件删除执行三次覆写（随机数据 → 0x00 → 0xFF），符合 NIST SP 800-88 建议
- **受保护进程**: 关键系统进程（csrss.exe、smss.exe、wininit.exe 等）禁止操作
- **自身保护**: 拒绝操作自身进程

---

## 开源组件与协议 / Open Source Components

<details>
<summary><b>点击展开 — 前端运行时依赖</b></summary>

| 组件 | 许可证 |
|------|--------|
| react, react-dom | MIT |
| zustand | MIT |
| framer-motion | MIT |
| lucide-react | ISC |
| clsx | MIT |
| @tauri-apps/api | MIT / Apache-2.0 |
| @tauri-apps/plugin-dialog / plugin-fs / plugin-shell | MIT / Apache-2.0 |

</details>

<details>
<summary><b>点击展开 — 前端开发依赖</b></summary>

| 组件 | 许可证 |
|------|--------|
| @tauri-apps/cli | MIT / Apache-2.0 |
| vite | MIT |
| @vitejs/plugin-react | MIT |
| typescript | Apache-2.0 |

</details>

<details>
<summary><b>点击展开 — Rust 后端依赖</b></summary>

| 组件 | 许可证 |
|------|--------|
| tauri 2.0 (tray-icon, image-ico) | Apache-2.0 OR MIT |
| tauri-plugin-shell / dialog / fs | MIT / Apache-2.0 |
| tauri-build | MIT / Apache-2.0 |
| serde, serde_json | MIT OR Apache-2.0 |
| tokio | MIT |
| windows 0.58 | MIT OR Apache-2.0 |
| sqlx (SQLite) | MIT OR Apache-2.0 |
| aes-gcm, sha2, rand, hex | Apache-2.0 OR MIT |
| chrono | MIT OR Apache-2.0 |
| libloading | ISC |
| thiserror, once_cell | MIT OR Apache-2.0 |
| uuid | MIT / Apache-2.0 |

</details>

<details>
<summary><b>点击展开 — Engine/ 第三方 DLL</b></summary>

| 组件 | 许可证 | 位置 |
|------|--------|------|
| LIEF | Apache 2.0 | `Engine/Axon/LIEF.dll` |
| LightGBM | MIT | `Engine/Axon/lib_lightgbm.dll` |
| spdlog | MIT | `Engine/Axon/spdlog.dll` |
| {fmt} | MIT | `Engine/Axon/fmt.dll` |

> **Axon 引擎**（`Engine/Axon/axon_engine.dll`）以 Apache 2.0 协议开源：
> [https://github.com/kelomina/Axon_ML](https://github.com/kelomina/Axon_ML)
>
> **Raven 引擎**（`Engine/Raven/raven_engine.dll`）为专有组件，以 MIT 许可证授权但仅限作为本应用的组成部分使用。
>
> **签名引擎**（`Engine/Axon/signature_engine.dll` + `Engine/Raven/signature_engine.dll`）为专有组件，与项目深度集成，适用上述限制。
>
> 完整第三方归属声明见 `Engine/THIRD-PARTY`。

</details>

<details>
<summary><b>点击展开 — 仓库内第三方代码</b></summary>

| 组件 | 许可证 |
|------|--------|
| Microsoft Research Detours 4.0.1 | MIT (`native/file_hook/src/Detours`) |
| pico.min.css | MIT (`assets/ui/pico.min.css`) |

</details>

---

## 许可证 / License

本项目基于 MIT 许可证开源，具体参见各组件对应的许可证文件。

This project is open source under the MIT License. See individual components for their respective licenses.

### 专有组件说明 / Proprietary Components

> **Raven 引擎** (`Engine/Raven/raven_engine.dll`) — 专有组件，以 MIT 许可证授权但仅限于作为本应用的组成部分使用。未经明确书面许可，不得单独分发、逆向工程或独立使用。
>
> **签名引擎** (`Engine/Axon/signature_engine.dll` + `Engine/Raven/signature_engine.dll`) — 专有组件，与项目深度集成，适用上述限制。
>
> **Axon 引擎** (`Engine/Axon/axon_engine.dll`) — 以 Apache 2.0 协议开源：
> [https://github.com/kelomina/Axon_ML](https://github.com/kelomina/Axon_ML)
>
> 详情见 `License` 文件中的 Engine DLL License Notice 章节。
