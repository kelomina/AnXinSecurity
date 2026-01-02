# AnXinSecurity

AnXinSecurity 是基于 Electron 的 Windows 安全监控与扫描应用，集成 ETW (Event Tracing for Windows) 进行进程行为采集，并通过后台安全引擎 `Axon_ml.exe` 提供健康检查与安全能力。进程行为监控可在设置页通过 `behaviorMonitoring.enabled` 开关控制是否写入行为数据库（不影响前端 ETW 实时推送）。文件检测可在设置页通过 `scan.commonExtensionsOnly` 开关控制是否仅检测 `exe/dll`（开启后其余扩展名一律跳过）。

ETW 支持按 Provider 分级跳过信任进程的事件（`etw.filters.trustedPid.skipProviders`），并可通过 `etw.providers.<Provider>.anyKeyword/allKeyword` 配置各 Provider 的 ETW Keyword 掩码以控制采集范围；同时可通过 `etw.logToConsole`/`etw.logParsedToConsole` 控制主进程控制台输出 ETW 事件（默认开启，受 `etw.consoleMaxPerSecond` 限流）。

## 启动顺序

应用启动初始化流程为：

1. 单实例检查：确保系统仅运行一个实例。
2. 环境与配置初始化：加载 `config/app.json`、多语言与本地扩展。
3. UI 预准备：创建 Splash 窗口、隐藏的主窗口与系统托盘。
4. 数据同步与扫描（阻塞）：确保后台安全引擎 `Axon_ml.exe` 可用并接入杀毒扫描，然后获取系统 PID 快照并执行拦截快照扫描，必须等待扫描完成后进入下一步。
5. 处理积压拦截弹窗：扫描期间积压的拦截任务从此阶段开始处理。
6. 安全组件启动：启动行为分析器与 ETW 工作线程；同时确保后台安全引擎 `Axon_ml.exe` 持续运行完成健康检查。
7. 销毁 Splash 窗口。
8. 显示主界面：调用 `win.show()` 呈现主界面。

## 开发与调试

- 启动开发模式：`npm run dev`
- 运行测试：`npm test`
- 构建安装包：`npm run build`
