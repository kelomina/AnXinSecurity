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
