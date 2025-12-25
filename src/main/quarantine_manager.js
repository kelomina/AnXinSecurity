const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const CryptoManager = require('./crypto_manager');
const { Worker } = require('worker_threads');
const os = require('os');

class QuarantineManager {
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

  initWorkers() {
    console.log(`QuarantineManager: Initializing ${this.maxWorkers} workers`);
    for (let i = 0; i < this.maxWorkers; i++) {
        this.createWorker(i);
    }
  }

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

  saveIndex() {
    try {
      fs.writeFileSync(this.indexPath, JSON.stringify(this.index, null, 2), 'utf-8');
    } catch (e) {
      console.error('QuarantineManager: Failed to save index', e);
    }
  }

  async quarantine(filePath) {
    console.log('QuarantineManager: Enqueue quarantine task', filePath);
    return new Promise((resolve, reject) => {
        this.taskQueue.push({ filePath, resolve, reject });
        this.processNext();
    });
  }

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

  getList() {
    console.log('QuarantineManager: getList called, count =', Array.isArray(this.index) ? this.index.length : -1)
    return this.index;
  }
}

const instance = new QuarantineManager();
instance.QuarantineManager = QuarantineManager;
module.exports = instance;
