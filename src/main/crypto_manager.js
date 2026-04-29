const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEFAULT_ITERATIONS = 600000;
const KEY_LENGTH = 16;
const SALT_LENGTH = 16;
const ALGORITHM = 'aes-128-gcm';

class CryptoManager {
  /**
   * - 函数: `constructor`
   * - Function: `constructor`
   * - 作用: 初始化 CryptoManager 的实例状态，并准备后续方法依赖的数据。
   * - Purpose: Initializes the CryptoManager instance state and prepares data required by later methods.
   * - 调用方: 当前类实例、静态入口或外部类使用方。
   * - Callers: Current class instances, static entry points, or external class consumers.
   * - 被调方: init。
   * - Callees: init.
   * - 变量说明: 无显式入参；局部变量用于保存当前函数的中间状态。
   * - Variables: No explicit parameters; local variables keep intermediate state for this function.
   * - 接入方式: 通过 `new CryptoManager(...)` 创建实例后接入。
   * - Integration: Integrate by creating an instance with `new CryptoManager(...)`.
   * - 错误处理: 主要依赖前置守卫与返回值控制流程，未在函数内部集中处理异常。
   * - Error Handling: Relies on guard clauses and return values for control flow and does not centralize exception handling inside the function.
   * - 关键词: CryptoManager | class | 函数 | function | 模块 | module | 接入 | integration | 错误处理 | error-handling
   */
  constructor(configPath, namespace = 'quarantine') {
    this.configPath = configPath;
    this.password = 'AnXinSecurityUserPassword';
    this.key = null;
    this.salt = null;
    this.namespace = namespace;
    this.init();
  }

  /**
 * - 函数: `setPassword`
 * - Function: `setPassword`
 * - 作用: 设置password状态，并同步影响当前模块内的后续判断。
 * - Purpose: Sets the password state and synchronizes the downstream decisions made inside this module.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `deriveKey`。
 * - Callees: `deriveKey`.
 * - 变量说明: `password` 为当前流程传入的password。
 * - Variables: `password` is the incoming password for this flow.
 * - 接入方式: 在当前模块内部直接调用 `setPassword(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `setPassword(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: 设置 | password | set | password | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  setPassword(password) {
    this.password = typeof password === 'string' ? password : String(password || '');
    this.deriveKey();
  }

  /**
 * - 函数: `init`
 * - Function: `init`
 * - 作用: 梳理并返回init负责的init局部处理结果。
 * - Purpose: Coordinates and returns the init processing result handled by init.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `deriveKey`、`fs.existsSync`、`fs.readFileSync`、`JSON.parse`、`path.dirname`、`fs.mkdirSync`。
 * - Callees: `deriveKey`, `fs.existsSync`, `fs.readFileSync`, `JSON.parse`, `path.dirname`, `fs.mkdirSync`.
 * - 变量说明: 无显式入参；`config`, `raw`, `salt` 为当前函数内部维护的中间状态或派生结果。
 * - Variables: No explicit parameters; `config`, `raw`, `salt` are the intermediate or derived values maintained inside the function.
 * - 接入方式: 在当前模块内部直接调用 `init(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `init(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 内部包含 `try/catch` 守卫，用于隔离局部异常并保持当前流程继续推进。
 * - Error Handling: Wraps sensitive work in `try/catch` so local failures are isolated and the current flow can continue.
 * - 关键词: init | init | 错误处理 | error handling | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
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

  /**
 * - 函数: `deriveKey`
 * - Function: `deriveKey`
 * - 作用: 梳理并返回deriveKey负责的键局部处理结果。
 * - Purpose: Coordinates and returns the key processing result handled by deriveKey.
 * - 调用方: `setPassword`、`init`、`模块顶层流程`。
 * - Callers: `setPassword`, `init`, `模块顶层流程`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: 无显式入参；当前函数主要依赖闭包状态、模块常量或内联表达式完成处理。
 * - Variables: No explicit parameters; this function mainly relies on closure state, module constants, or inline expressions.
 * - 接入方式: 在当前模块内部直接调用 `deriveKey(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `deriveKey(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: derive | 键 | derive | key | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
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
   * - 函数: `encryptFileStatic`
   * - Function: `encryptFileStatic`
   * - 作用: 加密 File Static 相关数据或流程，并返回当前模块所需结果。
   * - Purpose: encrypt File Static related data or workflow and returns the result required by this module.
   * - 调用方: encryptFile。
   * - Callers: encryptFile.
   * - 被调方: Promise, resolve, randomBytes, createCipheriv, createReadStream, createWriteStream, pipe, on 等。
   * - Callees: Promise, resolve, randomBytes, createCipheriv, createReadStream, createWriteStream, pipe, on and others.
   * - 变量说明: `sourcePath` 表示当前函数处理所需的输入参数；`destPath` 表示当前函数处理所需的输入参数；`key` 表示当前函数处理所需的输入参数。
   * - Variables: `sourcePath` is an input used by this function; `destPath` is an input used by this function; `key` is an input used by this function.
   * - 接入方式: 通过 `CryptoManager.encryptFileStatic(...)` 作为静态方法接入。
   * - Integration: Integrate through the static method `CryptoManager.encryptFileStatic(...)`.
   * - 错误处理: 内部捕获异常，并通过回退值、静默跳过或默认分支维持流程继续执行。
   * - Error Handling: Catches internal exceptions and keeps the flow running through fallback values, silent skips, or default branches.
   * - 关键词: 加密 | encrypt | 文件 | file | static | CryptoManager | class | 函数 | function | 模块
   */
  static async encryptFileStatic(sourcePath, destPath, key) {
    const iv = crypto.randomBytes(12);
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
 * - 函数: `encryptFile`
 * - Function: `encryptFile`
 * - 作用: 梳理并返回encryptFile负责的文件局部处理结果。
 * - Purpose: Coordinates and returns the file processing result handled by encryptFile.
 * - 调用方: `模块顶层流程`。
 * - Callers: `模块顶层流程`.
 * - 被调方: `encryptFileStatic`。
 * - Callees: `encryptFileStatic`.
 * - 变量说明: `sourcePath` 为当前流程传入的source路径；`destPath` 为当前流程传入的dest路径。
 * - Variables: `sourcePath` is the incoming source path for this flow; `destPath` is the incoming dest path for this flow.
 * - 接入方式: 在当前模块内部直接调用 `encryptFile(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `encryptFile(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: encrypt | 文件 | encrypt | file | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
  async encryptFile(sourcePath, destPath) {
    return CryptoManager.encryptFileStatic(sourcePath, destPath, this.key);
  }

  /**
 * - 函数: `decryptFile`
 * - Function: `decryptFile`
 * - 作用: 梳理并返回decryptFile负责的文件局部处理结果。
 * - Purpose: Coordinates and returns the file processing result handled by decryptFile.
 * - 调用方: `模块顶层流程`、`restore`。
 * - Callers: `模块顶层流程`, `restore`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `sourcePath` 为当前流程传入的source路径；`destPath` 为当前流程传入的dest路径；`ivHex` 为当前流程传入的ivhex；`iv`, `authTag` 为函数内部派生的中间状态。
 * - Variables: `sourcePath` is the incoming source path for this flow; `destPath` is the incoming dest path for this flow; `ivHex` is the incoming iv hex for this flow; `iv`, `authTag` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `decryptFile(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `decryptFile(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: decrypt | 文件 | decrypt | file | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
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

  /**
 * - 函数: `encryptText`
 * - Function: `encryptText`
 * - 作用: 梳理并返回encryptText负责的文本局部处理结果。
 * - Purpose: Coordinates and returns the text processing result handled by encryptText.
 * - 调用方: `模块顶层流程`、`saveRaw`。
 * - Callers: `模块顶层流程`, `saveRaw`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `plainText` 为当前流程传入的plain文本；`iv`, `cipher` 为函数内部派生的中间状态。
 * - Variables: `plainText` is the incoming plain text for this flow; `iv`, `cipher` are derived intermediate variables inside the function.
 * - 接入方式: 在当前模块内部直接调用 `encryptText(...)` 接入；新增同类流程时，优先复用本函数而不是重复编写分支逻辑。
 * - Integration: Integrate by calling `encryptText(...)` inside the current module; new sibling flows should reuse this function instead of duplicating branch logic.
 * - 错误处理: 主要依赖前置守卫与返回值控制流程，不在本函数内集中吞掉异常。
 * - Error Handling: Relies on guard clauses and return values for flow control instead of swallowing failures inside the function.
 * - 关键词: encrypt | 文本 | encrypt | text | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
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

  /**
 * - 函数: `decryptText`
 * - Function: `decryptText`
 * - 作用: 梳理并返回decryptText负责的文本局部处理结果。
 * - Purpose: Coordinates and returns the text processing result handled by decryptText.
 * - 调用方: `模块顶层流程`、`loadRaw`。
 * - Callers: `模块顶层流程`, `loadRaw`.
 * - 被调方: 当前函数主要依赖内联表达式、基础语句或外部对象方法完成处理。
 * - Callees: The function mainly relies on inline expressions, basic statements, or external object methods.
 * - 变量说明: `payload` 为当前流程传入的载荷；`iv`, `tag` 为函数内部派生的中间状态。
 * - Variables: `payload` is the incoming payload for this flow; `iv`, `tag` are derived intermediate variables inside the function.
 * - 接入方式: 通过当前工厂或模块返回值暴露；新增同类能力时，优先经由现有返回对象复用 `decryptText`。
 * - Integration: It is exposed through the current factory or module return value; new sibling capabilities should reuse `decryptText` through the existing returned object.
 * - 错误处理: 主要通过返回值与上游异常通道协同处理错误，失败会继续向调用方暴露。
 * - Error Handling: Relies on return values plus the upstream exception channel, so failures stay visible to callers.
 * - 关键词: decrypt | 文本 | decrypt | text | 复用 | 调用链 | call chain | 错误处理 | error handling | 复用
 */
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
