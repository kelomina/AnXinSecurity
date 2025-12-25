const { parentPort } = require('worker_threads');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const CryptoManager = require('../crypto_manager');
const { killRelatedProcess, forceDelete } = require('../utils');

parentPort.on('message', async (task) => {
  const { filePath, destDir, key } = task;
  
  try {
    if (!fs.existsSync(filePath)) {
        throw new Error('File not found: ' + filePath);
    }

    // 尝试终止进程
    await killRelatedProcess(filePath);

    // 生成唯一ID
    const id = crypto.randomUUID();
    const destPath = path.join(destDir, id + '.vir');
    const fileName = path.basename(filePath);

    // 加密
    let meta;
    try {
        // key 可能是 Uint8Array 或 Buffer，直接传给 encryptFileStatic 应该没问题，
        // 但为了保险，转为 Buffer
        const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
        meta = await CryptoManager.encryptFileStatic(filePath, destPath, keyBuf);
    } catch (err) {
        // 如果加密失败，尝试删除可能生成的半成品
        try { fs.unlinkSync(destPath); } catch {}
        throw new Error('Encryption failed: ' + err.message);
    }

    // 删除原文件
    try {
        await forceDelete(filePath);
    } catch (e) {
        // 删除原文件失败，回滚（删除备份）
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
