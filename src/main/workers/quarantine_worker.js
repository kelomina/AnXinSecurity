const { parentPort } = require('worker_threads');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const CryptoManager = require('../crypto_manager');
const { killRelatedProcess, forceDelete } = require('../utils');

/**
 * - 函数: `parentPort.on('message')` 回调
 * - Function: `parentPort.on('message')` callback
 * - 作用: 响应隔离任务消息，执行文件存在性校验、进程清理、加密落盘、原文件删除以及结果回传。
 * - Purpose: Handles quarantine task messages by validating the file, terminating related processes, encrypting the payload, deleting the original file, and posting the result back.
 * - 调用方: `parentPort.on('message')` 事件分发器。
 * - Callers: The `parentPort.on('message')` event dispatcher.
 * - 被调方: `existsSync`, `killRelatedProcess`, `randomUUID`, `join`, `basename`, `encryptFileStatic`, `forceDelete`, `postMessage`。
 * - Callees: `existsSync`, `killRelatedProcess`, `randomUUID`, `join`, `basename`, `encryptFileStatic`, `forceDelete`, `postMessage`.
 * - 变量说明: `task` 表示主线程下发的隔离任务；`filePath`、`destDir`、`key` 分别表示源文件、目标目录与加密密钥；`meta` 保存加密结果元数据。
 * - Variables: `task` is the quarantine job from the main thread; `filePath`, `destDir`, and `key` represent the source file, target directory, and encryption key; `meta` stores encryption metadata.
 * - 接入方式: 通过 Worker 线程消息协议接入，由主线程向当前 worker 发送 `message` 事件。
 * - Integration: Integrate through the worker-thread message contract, with the main thread sending a `message` event to this worker.
 * - 错误处理: 通过多层 `try/catch` 清理中间文件并将失败结果封装后回传主线程。
 * - Error Handling: Uses layered `try/catch` blocks to clean temporary files and post a failure payload back to the main thread.
 * - 关键词: 隔离 | quarantine | worker | 消息 | message | 加密 | encryption | 删除 | delete | 回传 | response
 */
parentPort.on('message', async (task) => {
  const { filePath, destDir, key } = task;
  
  try {
    if (!fs.existsSync(filePath)) {
        throw new Error('File not found: ' + filePath);
    }

    await killRelatedProcess(filePath);

    const id = crypto.randomUUID();
    const destPath = path.join(destDir, id + '.vir');
    const fileName = path.basename(filePath);

    let meta;
    try {
        const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
        meta = await CryptoManager.encryptFileStatic(filePath, destPath, keyBuf);
    } catch (err) {
        try { fs.unlinkSync(destPath); } catch {}
        throw new Error('Encryption failed: ' + err.message);
    }

    try {
        await forceDelete(filePath);
    } catch (e) {
        try { fs.unlinkSync(destPath); } catch {}
        throw new Error('Failed to delete original file (Access Denied or Busy). Quarantine aborted.');
    }

    const result = {
        success: true,
        record: {
            id,
            originalPath: filePath,
            fileName,
            date: new Date().toISOString(),
            size: meta.originalSize,
            iv: meta.iv,
            authTag: meta.authTag
        }
    };
    parentPort.postMessage(result);

  } catch (error) {
    parentPort.postMessage({
        success: false,
        error: error.message,
        filePath
    });
  }
});
