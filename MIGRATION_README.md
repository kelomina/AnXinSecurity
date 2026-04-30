# AnXin Security - Tauri Migration

## 项目状态

本项目正在从 Electron 迁移至 Tauri 框架。

### 已完成
- ✅ Rust 后端基础结构（src-tauri）
- ✅ FFI 绑定层（etw_bridge.dll, process_watcher.dll）
- ✅ Tauri Commands（配置、扫描、行为分析等）
- ✅ React 前端基础结构
- ✅ 状态管理（Zustand）
- ✅ API 封装层

### 进行中
- 🔄 Rust 依赖安装和编译
- 🔄 前端组件完善

### 待完成
- ⏳ 完整的功能测试
- ⏳ 性能优化
- ⏳ 打包发布

## 开发环境要求

1. **Rust 工具链**
   ```bash
   # 访问 https://rustup.rs/ 下载安装
   rustup-init.exe
   ```

2. **Node.js 18+**
   ```bash
   node --version  # 应 >= 18
   ```

3. **Visual Studio Build Tools 2019+**
   - 安装 "Desktop development with C++" 工作负载

## 开发命令

```bash
# 安装依赖
npm install

# 开发模式
npm run dev

# 构建前端
npm run build:frontend

# 构建完整应用
npm run build
```

## 项目结构

```
AnXinSecurity/
├── src-tauri/              # Rust 后端
│   ├── src/
│   │   ├── commands/       # Tauri Commands
│   │   ├── services/       # 核心服务
│   │   ├── ffi/           # FFI 绑定
│   │   ├── models/        # 数据模型
│   │   └── utils/         # 工具函数
│   ├── Cargo.toml
│   └── tauri.conf.json
├── src/                    # React 前端
│   ├── components/        # UI 组件
│   ├── api/               # API 封装
│   ├── stores/            # 状态管理
│   └── styles/            # 样式文件
├── archive/                # 归档的 Electron 代码
│   └── electron-legacy/
├── native/                 # C++ Native 组件（保留）
└── Engine/                 # 扫描引擎（保留）
```

## 架构说明

### Rust 后端
- 使用 `libloading` 动态加载 C++ DLL
- 通过 Tokio 异步运行时管理并发任务
- 使用 Tauri Events 向前端推送实时事件

### React 前端
- 使用 Vite 作为构建工具
- Zustand 进行状态管理
- 通过 `@tauri-apps/api` 与 Rust 后端通信

### Native 组件
- `etw_bridge.dll`: ETW 监控桥接
- `process_watcher.dll`: 进程监控
- `file_hook_detours.dll`: 文件钩子（通过注入方式工作）

## 迁移指南

详细迁移计划请参考：[electron-to-tauri-migration-plan.md](C:\Users\Saika\AppData\Roaming\Lingma\SharedClientCache\cli\specs\electron-to-tauri-migration-plan.md)
