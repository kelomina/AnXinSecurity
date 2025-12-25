const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

/**
 * 尝试终止占用文件的进程
 * @param {string} filePath 
 */
async function killRelatedProcess(filePath) {
  return new Promise((resolve) => {
    // 仅针对 Windows
    if (process.platform !== 'win32') return resolve();
    
    const fileName = path.basename(filePath);
    // 简单策略：如果文件名以 .exe 结尾，尝试杀掉同名进程
    if (!fileName.toLowerCase().endsWith('.exe')) return resolve();

    // console.log('Attempting to kill process', fileName);
    exec(`taskkill /F /IM "${fileName}"`, (err, stdout, stderr) => {
      // 忽略错误
      setTimeout(resolve, 500);
    });
  });
}

/**
 * 强制删除文件，带重试
 * @param {string} filePath 
 */
async function forceDelete(filePath) {
  for (let i = 0; i < 3; i++) {
    try {
      if (!fs.existsSync(filePath)) return;
      fs.unlinkSync(filePath);
      return;
    } catch (e) {
      // 尝试使用系统命令强制删除
      try {
          await new Promise((resolve, reject) => {
              exec(`del /f /q "${filePath}"`, (err) => {
                  if (err) reject(err);
                  else resolve();
              });
          });
          if (!fs.existsSync(filePath)) return;
      } catch {}
      
      await new Promise(r => setTimeout(r, 200 * (i + 1)));
    }
  }
  if (fs.existsSync(filePath)) {
      throw new Error('Cannot delete file: ' + filePath);
  }
}

module.exports = {
  killRelatedProcess,
  forceDelete
};
