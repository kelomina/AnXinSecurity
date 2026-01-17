(() => {
  const LOADER_URL = './assets/lottie/particle_loader.json'

  const FALLBACK_ANIM = {
    v: '5.7.4',
    fr: 60,
    ip: 0,
    op: 120,
    w: 200,
    h: 200,
    nm: 'anxin_particle_loader',
    ddd: 0,
    assets: [],
    layers: [
      {
        ddd: 0,
        ind: 1,
        ty: 4,
        nm: 'Ring',
        sr: 1,
        ks: {
          o: { a: 0, k: 100 },
          r: { a: 0, k: 0 },
          p: { a: 0, k: [100, 100, 0] },
          a: { a: 0, k: [0, 0, 0] },
          s: { a: 0, k: [100, 100, 100] }
        },
        shapes: [
          {
            ty: 'gr',
            it: [
              {
                ty: 'el',
                p: { a: 0, k: [0, 0] },
                s: { a: 0, k: [120, 120] },
                nm: 'Ellipse Path 1',
                mn: 'ADBE Vector Shape - Ellipse',
                hd: false
              },
              {
                ty: 'st',
                c: { a: 0, k: [0.298, 0.635, 1, 1] },
                o: { a: 0, k: 100 },
                w: { a: 0, k: 10 },
                lc: 2,
                lj: 2,
                ml: 4,
                d: [
                  { n: 'd', nm: 'Dash', v: { a: 0, k: 38 } },
                  { n: 'g', nm: 'Gap', v: { a: 0, k: 22 } },
                  { n: 'o', nm: 'Offset', v: { a: 1, k: [{ t: 0, s: [0] }, { t: 120, s: [-260] }] } }
                ],
                nm: 'Stroke 1',
                mn: 'ADBE Vector Graphic - Stroke',
                hd: false
              },
              {
                ty: 'tr',
                p: { a: 0, k: [0, 0] },
                a: { a: 0, k: [0, 0] },
                s: { a: 0, k: [100, 100] },
                r: { a: 1, k: [{ t: 0, s: [0] }, { t: 120, s: [360] }] },
                o: { a: 0, k: 100 },
                sk: { a: 0, k: 0 },
                sa: { a: 0, k: 0 },
                nm: 'Transform'
              }
            ],
            nm: 'Ellipse 1',
            np: 3,
            cix: 2,
            bm: 0,
            ix: 1,
            mn: 'ADBE Vector Group',
            hd: false
          }
        ],
        ip: 0,
        op: 120,
        st: 0,
        bm: 0
      }
    ],
    markers: []
  }

  const instances = new Map()
  let cachedData = null

  function animationsEnabled() {
    const body = document.body
    return !body || body.getAttribute('data-animations') !== 'off'
  }

  async function loadAnimData() {
    if (cachedData) return cachedData
    try {
      const res = await fetch(LOADER_URL, { cache: 'no-cache' })
      if (!res.ok) throw new Error('bad status')
      cachedData = await res.json()
      return cachedData
    } catch {
      cachedData = FALLBACK_ANIM
      return cachedData
    }
  }

  function ensureInstance(containerEl) {
    const key = containerEl.id || containerEl
    const existing = instances.get(key)
    if (existing) return existing
    if (!(window.lottie && typeof window.lottie.loadAnimation === 'function')) return null
    const inst = { containerEl, anim: null, active: false }
    instances.set(key, inst)
    return inst
  }

  async function start(containerId, spinnerId) {
    const containerEl = document.getElementById(containerId)
    const spinnerEl = spinnerId ? document.getElementById(spinnerId) : null
    if (!containerEl) return

    if (!animationsEnabled()) {
      containerEl.style.display = 'none'
      if (spinnerEl) spinnerEl.style.display = 'inline-block'
      return
    }

    const inst = ensureInstance(containerEl)
    if (!inst) {
      containerEl.style.display = 'none'
      if (spinnerEl) spinnerEl.style.display = 'inline-block'
      return
    }

    containerEl.style.display = 'inline-block'
    if (spinnerEl) spinnerEl.style.display = 'none'

    if (!inst.anim) {
      const data = await loadAnimData()
      inst.anim = window.lottie.loadAnimation({
        container: containerEl,
        renderer: 'svg',
        loop: true,
        autoplay: false,
        animationData: data
      })
      try {
        inst.anim.setSubframe(false)
      } catch {}
    }

    inst.active = true
    try {
      if (!document.hidden) inst.anim.play()
    } catch {}
  }

  function stop(containerId, spinnerId) {
    const containerEl = document.getElementById(containerId)
    const spinnerEl = spinnerId ? document.getElementById(spinnerId) : null
    if (spinnerEl) spinnerEl.style.display = 'inline-block'
    if (!containerEl) return
    containerEl.style.display = 'none'
    const key = containerEl.id || containerEl
    const inst = instances.get(key)
    if (!inst || !inst.anim) return
    inst.active = false
    try {
      inst.anim.pause()
    } catch {}
  }

  function bindModal(modalId, containerId, spinnerId) {
    const el = document.getElementById(modalId)
    if (!el) return
    el.addEventListener('shown.bs.modal', () => start(containerId, spinnerId))
    el.addEventListener('hidden.bs.modal', () => stop(containerId, spinnerId))
  }

  function onVisibilityChange() {
    const hidden = !!document.hidden
    for (const inst of instances.values()) {
      if (!inst.anim || !inst.active) continue
      try {
        if (hidden) inst.anim.pause()
        else inst.anim.play()
      } catch {}
    }
  }

  function init() {
    bindModal('engine-wait-modal', 'engine-wait-lottie', 'engine-wait-spinner')
    bindModal('loading-modal', 'loading-lottie', 'loading-spinner')
    bindModal('processing-modal', 'processing-lottie', 'processing-spinner')
    document.addEventListener('visibilitychange', onVisibilityChange)
  }

  if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', init)
    else init()
  }
})()
