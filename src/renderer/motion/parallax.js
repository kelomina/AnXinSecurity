(() => {
  let rafId = 0
  let lastScrollTop = 0
  let bound = false
  let contentEl = null
  let layers = []

  function animationsEnabled() {
    const body = document.body
    return !body || body.getAttribute('data-animations') !== 'off'
  }

  function collect() {
    contentEl = document.querySelector('.content')
    layers = contentEl ? Array.from(contentEl.querySelectorAll('[data-parallax-layer]')) : []
  }

  function apply(st) {
    for (const el of layers) {
      const rate = parseFloat(el.getAttribute('data-rate') || '1')
      const r = Number.isFinite(rate) ? rate : 1
      const ty = st * (1 - r)
      el.style.transform = `translate3d(0, ${ty}px, 0)`
    }
  }

  function reset() {
    for (const el of layers) {
      el.style.transform = ''
    }
  }

  function tick() {
    rafId = 0
    if (!contentEl || !layers.length) return
    if (!animationsEnabled()) {
      reset()
      return
    }
    apply(lastScrollTop)
  }

  function onScroll() {
    if (!contentEl) return
    lastScrollTop = contentEl.scrollTop || 0
    if (rafId) return
    rafId = requestAnimationFrame(tick)
  }

  function bind() {
    if (!contentEl || bound) return
    contentEl.addEventListener('scroll', onScroll, { passive: true })
    bound = true
  }

  function unbind() {
    if (!contentEl || !bound) return
    try {
      contentEl.removeEventListener('scroll', onScroll)
    } catch {}
    bound = false
  }

  function refresh() {
    if (rafId) cancelAnimationFrame(rafId)
    rafId = 0
    unbind()
    collect()
    if (!contentEl || !layers.length) return
    bind()
    onScroll()
  }

  function observeMotionFlag() {
    const body = document.body
    if (!body || typeof MutationObserver === 'undefined') return
    const mo = new MutationObserver(() => {
      if (!animationsEnabled()) reset()
      else onScroll()
    })
    mo.observe(body, { attributes: true, attributeFilter: ['data-animations'] })
  }

  function init() {
    refresh()
    observeMotionFlag()
    window.addEventListener('resize', refresh)
  }

  if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', init)
    else init()
  }
})()
