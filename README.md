# AnXin Security

一个基于 Electron 的安全防护应用，提供实时文件扫描、行为监控和威胁防护功能。

## 主要功能

- **实时文件扫描**: 基于签名数据库的文件安全扫描
- **行为监控**: 使用 ETW (Event Tracing for Windows) 监控进程行为
- **威胁防护**: 实时拦截和隔离恶意文件
- **进程监控**: 监控系统进程活动和文件操作
- **隔离管理**: 安全的文件隔离和恢复功能
- **启动项管理**: 系统启动项监控和防护

## 技术架构

- **前端**: Electron + HTML/CSS/JavaScript
- **原生模块**: C++ Native Modules (ETW Bridge, File Hook, Process Watcher)
- **数据库**: SQLite 行为日志存储
- **安全引擎**: 自定义扫描引擎和签名数据库

## 开源组件与协议

来源说明：以下许可证信息来自 package-lock.json 的 license 字段及仓库内第三方源码。

运行时依赖：
- @electron/rebuild — MIT
- bootstrap — MIT
- gsap — Standard 'no charge' license: https://gsap.com/standard-license
- koffi — MIT
- lottie-web — MIT

开发依赖：
- electron — MIT
- electron-builder — MIT
- storybook — MIT
- @storybook/html-vite — MIT
- vite — MIT

仓库内第三方代码与资源：
- Microsoft Research Detours 4.0.1 — MIT（native/file_hook/src/Detours）
- pico.min.css — Pico CSS 框架（MIT 许可证），品牌使用遵循 Pico CSS 品牌指南（assets/ui/pico.min.css）
- particle_loader.json — 项目自有 Lottie 动画资源（src/renderer/assets/lottie/particle_loader.json）

## 安装和使用

### 环境要求

- Node.js 16+
- npm 或 yarn
- Windows 10/11 操作系统
- Visual Studio 2019+ (用于原生模块编译)

### 安装步骤

1. 克隆项目仓库
```bash
git clone <repository-url>
cd AnXinSecurity
```

2. 安装依赖
```bash
npm install
```

3. 构建原生模块
```bash
npm run rebuild
```

4. 启动应用
```bash
npm run dev
```

### 生产环境构建

```bash
npm run build
```

## 开发指南

### 项目结构

```
AnXinSecurity/
├── src/                 # 源代码目录
│   ├── main/           # 主进程代码
│   │   ├── workers/    # 工作线程
│   │   └── *.js        # 核心模块
│   └── renderer/       # 渲染进程代码
├── native/             # 原生模块
│   ├── etw_bridge/    # ETW 桥接模块
│   ├── file_hook/      # 文件钩子模块
│   └── process_watcher/# 进程监控模块
├── config/             # 配置文件
├── data/               # 数据文件
└── assets/             # 静态资源

### 可用脚本

- `npm run dev` - 启动开发模式
- `npm run build` - 构建生产版本
- `npm run storybook` - 启动 Storybook 组件开发
- `npm run lint` - 代码语法检查

### 原生模块开发

项目包含多个 C++ 原生模块，使用 CMake 构建系统。如需修改原生代码：

1. 安装 Visual Studio 2019+ 和 C++ 开发工具
2. 修改 native/ 目录下的对应模块
3. 重新构建原生模块：`npm run rebuild`

### 贡献指南

1. Fork 项目仓库
2. 创建功能分支
3. 提交代码变更
4. 发起 Pull Request

## 许可证

本项目基于 MIT 许可证开源，具体参见各组件对应的许可证文件。
