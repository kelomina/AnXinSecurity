const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_ITERATIONS = 600000;
const KEY_LENGTH = 16;
const SALT_LENGTH = 16;
const ALGORITHM = 'aes-128-gcm';

class CryptoManager {
  constructor(configPath, namespace = 'quarantine') {
    this.configPath = configPath;
    this.password = 'AnXinSecurityUserPassword';
    this.key = null;
    this.salt = null;
    this.namespace = namespace;
    this.init();
  }

  init() {
    let config = {};
    try {
      if (fs.existsSync(this.configPath)) {
        const raw = fs.readFileSync(this.configPath, 'utf-8');
        config = JSON.parse(raw);
      }
    } catch (e) {
      console.error('CryptoManager: Failed to load config', e);
    }

    if (!config[this.namespace]) {
      config[this.namespace] = {};
    }

    if (!config[this.namespace].salt) {
      const salt = crypto.randomBytes(SALT_LENGTH);
      config[this.namespace].salt = salt.toString('hex');
      try {
        const dir = path.dirname(this.configPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(this.configPath, JSON.stringify(config, null, 2), 'utf-8');
      } catch (e) {
        console.error('CryptoManager: Failed to save config', e);
      }
    }

    this.salt = Buffer.from(config[this.namespace].salt, 'hex');
    this.deriveKey();
  }

  deriveKey() {
    this.key = crypto.pbkdf2Sync(
      this.password,
      this.salt,
      DEFAULT_ITERATIONS,
      KEY_LENGTH,
      'sha256'
    );
  }

  /**
   * 静态加密方法，用于 Worker 调用
   * @param {string} sourcePath 
   * @param {string} destPath 
   * @param {Buffer} key 
   */
  static async encryptFileStatic(sourcePath, destPath, key) {
    const iv = crypto.randomBytes(12); // GCM standard IV size
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    const input = fs.createReadStream(sourcePath);
    const output = fs.createWriteStream(destPath);

    return new Promise((resolve, reject) => {
      input.pipe(cipher).pipe(output);

      output.on('finish', () => {
        const authTag = cipher.getAuthTag();
        let originalSize = 0;
        try {
            originalSize = fs.statSync(sourcePath).size;
        } catch {}
        resolve({
          iv: iv.toString('hex'),
          authTag: authTag.toString('hex'),
          originalSize
        });
      });

      input.on('error', reject);
      output.on('error', reject);
      cipher.on('error', reject);
    });
  }

  /**
   * @param {string} sourcePath 源文件路径
   * @param {string} destPath 目标文件路径
   * @returns {Promise<{iv: string, authTag: string, originalSize: number}>}
   */
  async encryptFile(sourcePath, destPath) {
    return CryptoManager.encryptFileStatic(sourcePath, destPath, this.key);
  }

  /**
   * @param {string} sourcePath 加密文件路径
   * @param {string} destPath 目标文件路径
   * @param {string} ivHex IV (hex)
   * @param {string} authTagHex Auth Tag (hex)
   */
  async decryptFile(sourcePath, destPath, ivHex, authTagHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);

    const input = fs.createReadStream(sourcePath);
    const output = fs.createWriteStream(destPath);

    return new Promise((resolve, reject) => {
      input.pipe(decipher).pipe(output);

      output.on('finish', () => {
        resolve();
      });

      input.on('error', reject);
      output.on('error', reject);
      decipher.on('error', reject);
    });
  }

  encryptText(plainText) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(ALGORITHM, this.key, iv);
    const enc = Buffer.concat([cipher.update(Buffer.from(String(plainText), 'utf-8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      iv: iv.toString('hex'),
      authTag: tag.toString('hex'),
      data: enc.toString('base64')
    };
  }

  decryptText(payload) {
    if (!payload || !payload.iv || !payload.authTag || !payload.data) throw new Error('Invalid payload');
    const iv = Buffer.from(payload.iv, 'hex');
    const tag = Buffer.from(payload.authTag, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(tag);
    const buf = Buffer.concat([decipher.update(Buffer.from(payload.data, 'base64')), decipher.final()]);
    return buf.toString('utf-8');
  }
}

module.exports = CryptoManager;
