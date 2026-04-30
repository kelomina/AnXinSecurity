# 快速启动指南

## 前置条件检查

### 1. 验证环境
```bash
# 检查 Node.js（需要 >= 18）
node --version

# 检查 npm
npm --version

# 检查 Rust
rustc --version
cargo --version
```

### 2. 配置 Cargo 国内镜像（推荐中国大陆用户）

创建或编辑 `~/.cargo/config.toml`：

```toml
[source.crates-io]
replace-with = 'tuna'

[source.tuna]
registry = "sparse+https://mirrors.tuna.tsinghua.edu.cn/crates.io-index/"

[http]
check-revoke = false

[net]
git-fetch-with-cli = true
```

## 首次启动

### 步骤 1: 安装依赖
```bash
npm install
```

### 步骤 2: 验证 Native DLL 存在
确保以下文件存在：
- `native/win32-x64/etw_bridge.dll`
- `native/win32-x64/process_watcher.dll`
- `native/win32-x64/file_hook_detours.dll`

如果不存在，需要从归档中恢复或重新编译 C++ 组件。

### 步骤 3: 启动开发模式
```bash
npm run dev
```

这将：
1. 启动 Vite 开发服务器（端口 1421）
2. 编译 Rust 后端
3. 打开 Tauri 应用窗口

**首次编译可能需要 5-10 分钟**，因为需要下载和编译所有 Rust 依赖。

## 常见问题

### Q1: 编译卡在 "Updating crates.io index"
**解决方案**：配置国内镜像源（见上方）

### Q2: 提示 "Port 1421 is already in use"
**解决方案**：
```bash
# Windows - 查找并终止占用进程
netstat -ano | findstr :1421
taskkill /F /PID <进程ID>

# 或者修改 vite.config.ts 中的端口
```

### Q3: "DLL not found" 错误
**解决方案**：
1. 检查 `native/win32-x64/` 目录是否存在
2. 确保 DLL 文件未被杀毒软件隔离
3. 以管理员身份运行应用

### Q4: WebView2 未安装
**解决方案**：
Windows 10/11 通常已内置。如缺失，从以下地址下载安装：
https://developer.microsoft.com/en-us/microsoft-edge/webview2/

### Q5: Rust 编译错误
**解决方案**：
```bash
# 清理并重新编译
cd src-tauri
cargo clean
cargo build
```

## 生产构建

```bash
# 构建完整安装包
npm run build
```

生成的 NSIS 安装包位于：
`src-tauri/target/release/bundle/nsis/AnXinSecurity_1.0.0_x64-setup.exe`

## 调试技巧

### 查看前端控制台
在 Tauri 窗口右键 → 检查元素（DevTools）

### 查看 Rust 日志
```bash
# 设置日志级别
RUST_LOG=debug npm run dev
```

### 热重载
- 修改 React 代码会自动刷新
- 修改 Rust 代码会自动重新编译（可能需要几秒）

## 下一步

1. **测试核心功能**
   - 打开行为分析页面
   - 验证 ETW 事件是否正常显示
   - 测试暂停/恢复监控

2. **完善 UI**
   - 添加扫描进度条
   - 实现隔离区文件列表
   - 优化响应式布局

3. **性能优化**
   - 启用虚拟滚动（大量事件时）
   - 优化 Rust FFI 调用频率
   - 减少不必要的重渲染

## 获取帮助

- 迁移计划：`MIGRATION_README.md`
- 进度报告：`MIGRATION_PROGRESS.md`
- Tauri 文档：https://tauri.app/v2/
- Rust 文档：https://doc.rust-lang.org/

---

*最后更新：2026-04-29*
