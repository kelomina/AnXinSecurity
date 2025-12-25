
let logUnsubscriber = null;

function initUpdate() {
  console.log('渲染进程: 初始化更新页 (UI组件已移除)');
  const t = window.t || ((k) => k);
  const title = document.getElementById('update-title');
  if (title) title.textContent = t('nav_update'); 
  const desc = document.getElementById('update-desc');
  if (desc) desc.textContent = t('update_desc');
  
  const notImpl = document.getElementById('update-not-implemented');
  if (notImpl) notImpl.textContent = t('feature_not_implemented');

  if (logUnsubscriber) {
    logUnsubscriber();
    logUnsubscriber = null;
  }
}

window.initUpdate = initUpdate;
