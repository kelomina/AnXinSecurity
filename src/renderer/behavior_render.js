(function (root) {
  function defaultYield() {
    return new Promise((resolve) => requestAnimationFrame(() => resolve()))
  }

  function makeYieldFn(yieldFn) {
    if (typeof yieldFn === 'function') return yieldFn
    if (typeof requestAnimationFrame === 'function') return defaultYield
    return () => Promise.resolve()
  }

  async function renderProcessSelectAsync(opts) {
    const o = opts && typeof opts === 'object' ? opts : {}
    const sel = o.sel
    if (!sel) return
    const list = Array.isArray(o.list) ? o.list : []
    const t = typeof o.t === 'function' ? o.t : ((k) => k)
    const getBaseName = typeof o.getBaseName === 'function' ? o.getBaseName : (() => '')
    const batchSize = Number.isFinite(o.batchSize) ? Math.max(50, Math.min(2000, Math.floor(o.batchSize))) : 200
    const yieldFn = makeYieldFn(o.yieldFn)
    const shouldContinue = typeof o.shouldContinue === 'function' ? o.shouldContinue : (() => true)
    const onProgress = typeof o.onProgress === 'function' ? o.onProgress : null
    const onFirstBatch = typeof o.onFirstBatch === 'function' ? o.onFirstBatch : null
    const total = list.length >>> 0

    if (!shouldContinue()) return
    sel.innerHTML = ''
    const optAll = (sel.ownerDocument && sel.ownerDocument.createElement)
      ? sel.ownerDocument.createElement('option')
      : (typeof document !== 'undefined' && document.createElement ? document.createElement('option') : null)
    if (optAll) {
      optAll.value = ''
      optAll.textContent = t('behavior_all_processes')
      sel.appendChild(optAll)
    }

    for (let i = 0; i < list.length; i += batchSize) {
      if (!shouldContinue()) return
      const frag = (sel.ownerDocument && sel.ownerDocument.createDocumentFragment)
        ? sel.ownerDocument.createDocumentFragment()
        : (typeof document !== 'undefined' && document.createDocumentFragment ? document.createDocumentFragment() : null)
      const slice = list.slice(i, i + batchSize)
      for (const p of slice) {
        if (!shouldContinue()) return
        const pid = Number.isFinite(p && p.pid) ? p.pid : null
        if (pid == null) continue
        const image = typeof p.image === 'string' ? p.image : ''
        const name = (typeof p.name === 'string' && p.name) ? p.name : getBaseName(image)
        const opt = (sel.ownerDocument && sel.ownerDocument.createElement)
          ? sel.ownerDocument.createElement('option')
          : (typeof document !== 'undefined' && document.createElement ? document.createElement('option') : null)
        if (!opt) continue
        opt.value = String(pid)
        opt.textContent = name ? `${pid} - ${name}` : String(pid)
        if (frag && frag.appendChild) frag.appendChild(opt)
        else sel.appendChild(opt)
      }
      if (frag && frag.childNodes && frag.childNodes.length > 0) sel.appendChild(frag)
      if (onProgress) {
        const done = Math.min(total, i + slice.length)
        try { onProgress(total, done) } catch {}
      }
      if (i === 0 && onFirstBatch) {
        try { onFirstBatch() } catch {}
      }
      if (i + batchSize < list.length) {
        await yieldFn()
        if (!shouldContinue()) return
      }
    }
  }

  root.behaviorRender = root.behaviorRender || {}
  root.behaviorRender.renderProcessSelectAsync = renderProcessSelectAsync

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { renderProcessSelectAsync }
  }
})(typeof window !== 'undefined' ? window : globalThis)
