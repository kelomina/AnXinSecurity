# 安全测试探测配置说明
# Security Test Probe Configuration Reference

本文档说明 PEB 断链和反射加载安全测试探测 DLL 的环境变量配置方法。

---

## 构建选项 (CMake Options)

| CMake 选项 | 默认值 | 说明 |
|-----------|--------|------|
| `BUILD_PEB_REAL_PROBE` | `OFF` | 构建真实 PEB 断链探测 DLL (`peb_unlink_real_payload.dll`) |
| `BUILD_REFLECTIVE_REAL_PROBE` | `OFF` | 构建真实反射加载探测 DLL (`reflective_load_real_payload.dll`) |
| `BUILD_PEB_PROBE` | `OFF` | 构建模拟 PEB 断链文物探测 DLL（已有，非本次新增） |
| `BUILD_REFLECTIVE_PROBE` | `OFF` | 构建模拟反射加载文物探测 DLL（已有，非本次新增） |

构建示例（在 `native/file_hook` 目录下）：

```bash
cmake -B build-x64 -G "Visual Studio 17 2022" -A x64 \
  -DBUILD_PEB_REAL_PROBE=ON \
  -DBUILD_REFLECTIVE_REAL_PROBE=ON
cmake --build build-x64 --config Release
```

> 注意：先执行 configure 创建 vcxproj，然后 build 编译。已存在 build-x64 时需要先删除或者重新 configure。

---

## 运行时环境变量 (Runtime Environment Variables)

### PEB 断链探测 (peb_unlink_real_payload.dll)

| 环境变量 | 类型 | 默认值 | 有效值 | 说明 |
|---------|------|--------|--------|------|
| `ANXIN_PEB_REAL_PROBE_MODE` | string | `simulate` | `simulate`, `real`, `both` | 探测模式 |
| `ANXIN_PEB_REAL_PROBE_HOLD_MS` | DWORD | `600000` | 1 – 3600000 | 保持断链状态的毫秒数 |

### 反射加载探测 (reflective_load_real_payload.dll)

| 环境变量 | 类型 | 默认值 | 有效值 | 说明 |
|---------|------|--------|--------|------|
| `ANXIN_REFLECTIVE_REAL_PROBE_MODE` | string | `simulate` | `simulate`, `real`, `both` | 探测模式 |
| `ANXIN_REFLECTIVE_REAL_PROBE_HOLD_MS` | DWORD | `600000` | 1 – 3600000 | 保持加载状态的毫秒数 |

---

## 模式说明

### `simulate`（模拟模式，默认）
- 仅构造 `MEM_PRIVATE + PAGE_EXECUTE_READ` 内存文物
- 不实际操纵系统链表或执行反射加载
- 最安全，适合初步验证内存异常检测能力

### `real`（真实模式）
- PEB 断链：实际操纵 PEB 的 InLoadOrder/InMemoryOrder/InInitializationOrder 链表
- 反射加载：完整执行 PE 解析 → 节映射 → 重定位 → 导入解析 → DllMain 调用
- 适合验证安芯的「模块链一致性检测」和其它高级检测能力

### `both`（两者模式）
- 同时执行模拟和真实两种模式
- 在同一进程中产生两种不同的检测信号

---

## 使用示例

```powershell
# 仅使用模拟模式（默认，无需设置环境变量）
set ANXIN_PEB_REAL_PROBE_MODE=simulate

# 仅使用真实模式
set ANXIN_PEB_REAL_PROBE_MODE=real

# 同时使用两种模式
set ANXIN_PEB_REAL_PROBE_MODE=both

# 设置保持时间为 30 秒（方便快速测试）
set ANXIN_PEB_REAL_PROBE_HOLD_MS=30000

# 反射加载真实模式，保持 2 分钟
set ANXIN_REFLECTIVE_REAL_PROBE_MODE=real
set ANXIN_REFLECTIVE_REAL_PROBE_HOLD_MS=120000
```

---

## 安全注意事项

1. **默认安全模式**：所有探测默认为 `simulate` 模式，不实施真实系统操作
2. **仅用于防御验证**：这些探测专为测试安芯安全软件的检测能力设计
3. **受控环境使用**：仅在专用测试环境中使用，禁止在生产环境运行
4. **审计日志**：所有探测操作通过 `OutputDebugStringA` 输出详细日志
5. **自清理**：真实模式会在退出前恢复系统状态（PEB 断链恢复、反射加载卸载）
6. **标记识别**：所有内存文物和日志包含 `DEFENSIVE_TEST_ARTIFACT_NOT_MALICIOUS` 标记

---

## 与安芯检测能力的对应关系

| 探测类型 | 模式 | 预期安芯检测信号 |
|---------|------|----------------|
| PEB 断链 | simulate | 内存异常检测：`MEM_PRIVATE` + `PAGE_EXECUTE_READ` + MZ/PE 结构 |
| PEB 断链 | real | 模块链一致性检测：`module_chain_unlinked_image` |
| 反射加载 | simulate | 内存异常检测：`MEM_PRIVATE` + `PAGE_EXECUTE_READ` + PE 节结构 |
| 反射加载 | real | 内存异常 + 无 LoadLibrary 事件 + 模块不在 PEB 列表 |
