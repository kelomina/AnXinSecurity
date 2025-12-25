const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

async function killRelatedProcess(filePath) {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve();
    
    const fileName = path.basename(filePath);
    if (!fileName.toLowerCase().endsWith('.exe')) return resolve();

    exec(`taskkill /F /IM "${fileName}"`, (err, stdout, stderr) => {
      setTimeout(resolve, 500);
    });
  });
}

async function forceDelete(filePath) {
  for (let i = 0; i < 3; i++) {
    try {
      if (!fs.existsSync(filePath)) return;
      fs.unlinkSync(filePath);
      return;
    } catch (e) {
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
