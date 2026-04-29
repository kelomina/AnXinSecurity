const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const CryptoManager = require('./crypto_manager');
const { Worker } = require('worker_threads');
const os = require('os');

class QuarantineManager {
  /**
   * - 函数: `constructor`
   * - Function: `constructor`
   * - 作用: 初始化 QuarantineManager 的实例状态，并准备后续方法依赖的数据。
   * - Purpose: Initializes the QuarantineManager instance state and prepares data required by later methods.
   * - 调用方: 当前类实例、静态入口或外部类使用方。
   * - Callers: Current class instances, static entry points, or external class consumers.
   * - 被调方: CryptoManager, loadIndex, initWorkers, resolve, join, existsSync, mkdirSync, error 等。
   * - Callees: CryptoManager, loadIndex, initWorkers, resolve, join, existsSync, mkdirSync, error and others.
   * - 变量说明: 无显式入参；局部变量用于保存当前函数的中间状态。
   * - Variables: No explicit parameters; local variables keep intermediate state for this function.
   * - 接入方式: 通过 `new QuarantineManager(...)` 创建实例后接入。
   * - Integration: Integrate by creating an instance with `new QuarantineManager(...)`.
   * - 错误处理: 内部捕获异常，并通过回退值、静默跳过或默认分支维持流程继续执行。
   * - Error Handling: Catches internal exceptions and keeps the flow running through fallback values, silent skips, or default branches.
   * - 关键词: QuarantineManager | class | 函数 | function | 模块 | module | 接入 | integration | 错误处理 | error-handling
   */
  constructor(baseDir = null) {
    const rootDir = baseDir || path.resolve(__dirname, '../../');
    this.configPath = path.join(rootDir, 'config/app.json');
    this.indexPath = path.join(rootDir, 'config/quarantine_index.json');
    this.storageDir = path.join(rootDir, 'vir');

    if (!fs.existsSync(this.storageDir)) {
      try {
        fs.mkdirSync(this.storageDir, { recursive: true });
      } catch (e) {
        console.error('QuarantineManager: Failed to create storage dir', e);
      }
    }

    this.crypto = new CryptoManager(this.configPath);
    this.index = this.loadIndex();

    this.workers = [];
    this.taskQueue = [];
    this.maxWorkers = Math.max(1, (os.cpus().length || 4) - 1);
    this.initWorkers();
  }

  /**
 * - 函数: `initWorkers`
 * - Function: `initWorkers`
 * - 作用: 按当前 CPU 配额预创建隔离 worker 池，为后续隔离请求提供可复用的并发执行器，避免每次隔离都重复拉起新线程。
 * - Purpose: Pre-creates the quarantine worker pool based on the current CPU quota so later quarantine jobs reuse warm workers instead of spawning a new thread for every request.
 * - 调用方: `constructor` 在 `QuarantineManager` 初始化阶段调用。
 * - Callers: Called by `constructor` during `QuarantineManager` initialization.
 * - 被调方: `createWorker`。
 * - Callees: `createWorker`.
 * - 变量说明: 无显式入参；`this.maxWorkers` 表示计划创建的 worker 数；`i` 为当前初始化到的 worker 序号。
 * - Variables: No explicit parameters; `this.maxWorkers` is the planned worker count; `i` is the index of the worker currently being created.
 * - 接入方式: 仅作为 `QuarantineManager` 内部启动步骤使用；新增池化策略时应优先在本函数集中调整，而不是散落到调用点里创建 worker。
 * - Integration: Use it only as an internal startup step of `QuarantineManager`; changes to pooling strategy should be centralized here instead of spawning workers ad hoc at call sites.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: worker池初始化 | worker pool init | 并发隔离 | concurrent quarantine | 预热线程 | warm workers | QuarantineManager | createWorker | 启动阶段 | bootstrap
 */
  initWorkers() {
    console.log(`QuarantineManager: Initializing ${this.maxWorkers} workers`);
    for (let i = 0; i < this.maxWorkers; i++) {
        this.createWorker(i);
    }
  }

  /**
 * - 函数: `createWorker`
 * - Function: `createWorker`
 * - 作用: 创建单个隔离 worker，并把任务完成、失败重建、索引持久化和队列继续调度的逻辑绑定到该 worker 生命周期上。
 * - Purpose: Creates a single quarantine worker and binds task completion, crash recovery, index persistence, and continued queue scheduling to that worker’s lifecycle.
 * - 调用方: `initWorkers` 在池初始化时调用；worker 异常退出后也会由本函数递归重建同编号 worker。
 * - Callers: Called by `initWorkers` during pool bootstrap, and recursively reused to recreate a worker with the same id after a worker failure.
 * - 被调方: `Worker`、`saveIndex`、`processNext`、`path.join`。
 * - Callees: `Worker`, `saveIndex`, `processNext`, and `path.join`.
 * - 变量说明: `id` 为 worker 编号；`workerPath` 为隔离 worker 脚本路径；`wObj` 保存 worker 实例、忙闲状态和当前任务引用。
 * - Variables: `id` is the worker identifier; `workerPath` is the quarantine-worker script path; `wObj` stores the worker instance, busy flag, and current task reference.
 * - 接入方式: 仅供 `QuarantineManager` 内部管理 worker 池时调用；外部不应直接持有内部 worker，而应通过 `quarantine()` 间接使用。
 * - Integration: Use only inside `QuarantineManager` while managing the worker pool; external code should not hold raw workers and should go through `quarantine()` instead.
 * - 错误处理: 任务失败时会拒绝当前任务 Promise；worker 线程报错时会终止旧线程、移出池、立刻补建新 worker，并继续驱动积压队列。
 * - Error Handling: Rejects the current task promise when a task fails; on worker errors it terminates the old thread, removes it from the pool, recreates a replacement immediately, and keeps the backlog moving.
 * - 关键词: worker重建 | worker recreation | 隔离线程 | quarantine worker | 任务回传 | task completion | 索引持久化 | index persistence | 崩溃恢复 | crash recovery
 */
  createWorker(id) {
    const workerPath = path.join(__dirname, 'workers/quarantine_worker.js');
    const worker = new Worker(workerPath);
    const wObj = { worker, busy: false, id, currentTask: null };

    worker.on('message', (result) => {
        const currentTask = wObj.currentTask;
        wObj.busy = false;
        wObj.currentTask = null;

        if (currentTask) {
            if (result.success) {
                this.index.push(result.record);
                this.saveIndex(); 
                currentTask.resolve(result.record);
            } else {
                currentTask.reject(new Error(result.error));
            }
        }
        this.processNext();
    });

    worker.on('error', (err) => {
        console.error(`QuarantineManager: Worker ${id} error`, err);
        if (wObj.currentTask) {
            wObj.currentTask.reject(err);
        }
        wObj.busy = false;
        wObj.currentTask = null;
        worker.terminate();
        this.workers = this.workers.filter(w => w.id !== id);
        
        this.createWorker(id);
        this.processNext();
    });

    this.workers.push(wObj);
  }

  /**
 * - 函数: `processNext`
 * - Function: `processNext`
 * - 作用: 从隔离任务队列中取出下一项并分配给空闲 worker，是 `QuarantineManager` 在主线程侧实现串行入队、并发执行的核心调度点。
 * - Purpose: Pulls the next quarantine task from the queue and assigns it to an idle worker, serving as the core dispatcher that combines serialized enqueueing with parallel execution on the main thread.
 * - 调用方: `quarantine` 在新任务入队后调用；`createWorker` 在任务完成或 worker 重建后继续唤醒调度。
 * - Callers: Called by `quarantine` after enqueueing a new task, and by `createWorker` after task completion or worker recreation to resume scheduling.
 * - 被调方: `postMessage`。
 * - Callees: `postMessage`.
 * - 变量说明: 无显式入参；`availableWorker` 表示当前找到的空闲 worker；`task` 保存待隔离文件及其 `resolve/reject` 回调。
 * - Variables: No explicit parameters; `availableWorker` is the idle worker found for dispatch; `task` stores the target file plus its `resolve/reject` callbacks.
 * - 接入方式: 仅在 `QuarantineManager` 内部使用；新增队列策略时应在这里统一控制，而不是在调用处直接向 worker 发消息。
 * - Integration: Use only inside `QuarantineManager`; queue-policy changes should be centralized here rather than posting directly to workers from call sites.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 队列调度 | queue dispatch | 空闲worker | idle worker | 隔离任务 | quarantine task | 主线程调度 | main-thread scheduler | processNext | worker pool
 */
  processNext() {
      if (this.taskQueue.length === 0) return;
      const availableWorker = this.workers.find(w => !w.busy);
      if (!availableWorker) return;

      const task = this.taskQueue.shift();
      availableWorker.busy = true;
      availableWorker.currentTask = task;
      
      availableWorker.worker.postMessage({
          filePath: task.filePath,
          destDir: this.storageDir,
          key: this.crypto.key
      });
  }

  /**
 * - 函数: `loadIndex`
 * - Function: `loadIndex`
 * - 作用: 加载index资源，并返回后续逻辑可以直接复用的数据或实例。
 * - Purpose: Loads the index resource and returns data or instances that downstream logic can reuse.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `fs.existsSync`、`fs.readFileSync`、`JSON.parse`。
 * - Callees: `fs.existsSync`, `fs.readFileSync`, `JSON.parse`.
 * - 变量说明: 无显式入参；`raw`, `data` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `raw`, `data` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `loadIndex(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `loadIndex(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部捕获异常并回退到安全默认值，尽量避免辅助逻辑中断主流程。
 * - Error Handling: Catches local failures and falls back to safe defaults so helper logic does not break the main flow.
 * - 关键词: 加载 | index | load | index | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  loadIndex() {
    try {
      if (fs.existsSync(this.indexPath)) {
        const raw = fs.readFileSync(this.indexPath, 'utf-8');
        const data = JSON.parse(raw);
        console.log('QuarantineManager: Loaded index, count =', data.length);
        return data;
      }
    } catch (e) {
      console.error('QuarantineManager: Failed to load index', e);
    }
    return [];
  }

  /**
 * - 函数: `saveIndex`
 * - Function: `saveIndex`
 * - 作用: 梳理并返回saveIndex负责的index局部处理结果。
 * - Purpose: Coordinates and returns the index processing result handled by saveIndex.
 * - 调用方: `createWorker`、`模块顶层流程`、`restore`。
 * - Callers: `createWorker`, `模块顶层流程`, `restore`.
 * - 被调方: `fs.writeFileSync`、`JSON.stringify`。
 * - Callees: `fs.writeFileSync`, `JSON.stringify`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `saveIndex(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `saveIndex(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: save | index | save | index | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  saveIndex() {
    try {
      fs.writeFileSync(this.indexPath, JSON.stringify(this.index, null, 2), 'utf-8');
    } catch (e) {
      console.error('QuarantineManager: Failed to save index', e);
    }
  }

  /**
 * - 函数: `quarantine`
 * - Function: `quarantine`
 * - 作用: 接收待隔离文件路径，生成一个可等待结果的任务 Promise，并把任务推入隔离队列交由 worker 池异步执行。
 * - Purpose: Accepts a file path to quarantine, creates a task promise that callers can await, and enqueues the job for asynchronous execution by the quarantine worker pool.
 * - 调用方: 主进程中的扫描命中、拦截处置或用户手动隔离流程通过导出的 `quarantine()` 入口调用。
 * - Callers: Invoked through the exported `quarantine()` entry by main-process flows such as scan hits, interception handling, or user-triggered quarantine actions.
 * - 被调方: `push`、`processNext`。
 * - Callees: `push`, `processNext`.
 * - 变量说明: `filePath` 为待隔离的源文件路径；入队任务对象中还会附带 `resolve/reject`，用于把 worker 执行结果回传给调用方。
 * - Variables: `filePath` is the source file to quarantine; the queued task object also carries `resolve/reject` so the worker result can be bridged back to the caller.
 * - 接入方式: 通过导出实例 `quarantineManager.quarantine(filePath)` 接入；外部不应自行拼接 worker 消息或直接改写 `taskQueue`。
 * - Integration: Use `quarantineManager.quarantine(filePath)` on the exported instance; callers should not craft raw worker messages or mutate `taskQueue` directly.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 文件隔离 | file quarantine | 入队任务 | queued task | Promise结果 | promised result | worker池 | worker pool | 异步处置 | async remediation
 */
  async quarantine(filePath) {
    console.log('QuarantineManager: Enqueue quarantine task', filePath);
    return new Promise((resolve, reject) => {
        this.taskQueue.push({ filePath, resolve, reject });
        this.processNext();
    });
  }

  /**
 * - 函数: `restore`
 * - Function: `restore`
 * - 作用: 根据隔离索引记录恢复原始文件，完成解密、重建目标目录、删除 `.vir` 文件并同步更新隔离索引，是隔离回滚链路的核心入口。
 * - Purpose: Restores the original file from a quarantine index record by decrypting it, recreating the destination directory, removing the `.vir` payload, and updating the quarantine index, making it the core rollback entry for quarantine recovery.
 * - 调用方: 主进程中的手动恢复、扫描结果回滚或初始化恢复流程通过导出的 `restore()` 入口调用。
 * - Callers: Invoked through the exported `restore()` entry by manual restore flows, scan-result rollback, or startup recovery paths in the main process.
 * - 被调方: `decryptFile`、`saveIndex`、`path.join`、`fs.existsSync`、`path.dirname`、`fs.mkdirSync`。
 * - Callees: `decryptFile`, `saveIndex`, `path.join`, `fs.existsSync`, `path.dirname`, `fs.mkdirSync`.
 * - 变量说明: `id` 为隔离记录 ID；`record` 为索引中的隔离元数据；`sourcePath` 指向实际加密存储的 `.vir` 文件；`destDir` 为原文件恢复目录。
 * - Variables: `id` is the quarantine record id; `record` is the indexed quarantine metadata; `sourcePath` points to the encrypted `.vir` payload; `destDir` is the restore destination directory.
 * - 接入方式: 通过导出实例 `quarantineManager.restore(id)` 接入；外部若要恢复文件，应始终依赖索引记录而不是直接操作 `.vir` 文件。
 * - Integration: Use `quarantineManager.restore(id)` on the exported instance; restore flows should always rely on indexed records instead of manipulating `.vir` files directly.
 * - 错误处理: 找不到索引记录或隔离文件时会显式抛错；删除加密文件失败只做容错处理，不影响已成功恢复的原文件和索引更新。
 * - Error Handling: Throws explicitly when the index record or quarantined payload is missing; failures while deleting the encrypted file are tolerated so a successfully restored original file is not rolled back.
 * - 关键词: 恢复隔离文件 | restore quarantined file | 索引回滚 | index rollback | 解密恢复 | decrypt restore | 原路径重建 | destination recreate | quarantine rollback
 */
  async restore(id) {
    const record = this.index.find(r => r.id === id);
    if (!record) throw new Error('Record not found');

    const sourcePath = path.join(this.storageDir, id + '.vir');
    if (!fs.existsSync(sourcePath)) throw new Error('Quarantined file not found');

    const destDir = path.dirname(record.originalPath);
    if (!fs.existsSync(destDir)) {
      fs.mkdirSync(destDir, { recursive: true });
    }

    await this.crypto.decryptFile(sourcePath, record.originalPath, record.iv, record.authTag);

    try {
      fs.unlinkSync(sourcePath);
    } catch {}
    
    this.index = this.index.filter(r => r.id !== id);
    this.saveIndex();
  }

  async delete(id) {
    const record = this.index.find(r => r.id === id);
    if (record) {
      const sourcePath = path.join(this.storageDir, id + '.vir');
      if (fs.existsSync(sourcePath)) {
        try {
          fs.unlinkSync(sourcePath);
        } catch {}
      }
      this.index = this.index.filter(r => r.id !== id);
      this.saveIndex();
    }
  }

  /**
 * - 函数: `getList`
 * - Function: `getList`
 * - 作用: 读取并汇总列出，返回当前流程消费的快照或配置结果。
 * - Purpose: Reads and aggregates the list into a snapshot or config result for the current flow.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `Array.isArray`。
 * - Callees: `Array.isArray`.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `getList(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `getList(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 获取 | 列出 | get | list | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  getList() {
    console.log('QuarantineManager: getList called, count =', Array.isArray(this.index) ? this.index.length : -1)
    return this.index;
  }
}

const instance = new QuarantineManager();
instance.QuarantineManager = QuarantineManager;
module.exports = instance;
