(() => {
  function animationsEnabled() {
    const body = document.body
    return !body || body.getAttribute('data-animations') !== 'off'
  }

  function parseCssTimeMs(raw) {
    const s = typeof raw === 'string' ? raw.trim() : ''
    if (!s) return null
    if (s.endsWith('ms')) {
      const v = parseFloat(s.slice(0, -2))
      return Number.isFinite(v) ? v : null
    }
    if (s.endsWith('s')) {
      const v = parseFloat(s.slice(0, -1))
      return Number.isFinite(v) ? v * 1000 : null
    }
    const v = parseFloat(s)
    return Number.isFinite(v) ? v : null
  }

  function getMotionVarMs(name, fallbackMs) {
    try {
      const v = getComputedStyle(document.documentElement).getPropertyValue(name)
      const ms = parseCssTimeMs(v)
      return Number.isFinite(ms) ? ms : fallbackMs
    } catch {
      return fallbackMs
    }
  }

  function numAttr(el, name, fallback) {
    const v = el.getAttribute(name)
    const n = v != null ? parseFloat(v) : NaN
    return Number.isFinite(n) ? n : fallback
  }

  function strAttr(el, name, fallback) {
    const v = el.getAttribute(name)
    return (typeof v === 'string' && v.trim()) ? v.trim() : fallback
  }

  function gsapRef() {
    return (typeof window !== 'undefined' && window.gsap) ? window.gsap : null
  }

  function fadeIn(el, opts) {
    const gsap = gsapRef()
    const enabled = animationsEnabled()
    const durationMs = Math.max(0, opts.durationMs || getMotionVarMs('--motion-dur-enter', 250))
    const delayMs = Math.max(0, opts.delayMs || 0)
    const ease = opts.ease || 'power3.out'
    if (!enabled || !gsap) {
      el.style.opacity = '1'
      el.style.filter = ''
      el.style.transform = ''
      return Promise.resolve()
    }
    gsap.set(el, { opacity: 0 })
    return new Promise(resolve => {
      gsap.to(el, {
        opacity: 1,
        duration: durationMs / 1000,
        delay: delayMs / 1000,
        ease,
        overwrite: true,
        onComplete: () => {
          try { gsap.set(el, { clearProps: 'opacity,filter,transform' }) } catch {}
          resolve()
        }
      })
    })
  }

  function slideIn(el, opts) {
    const gsap = gsapRef()
    const enabled = animationsEnabled()
    const durationMs = Math.max(0, opts.durationMs || getMotionVarMs('--motion-dur-enter', 250))
    const delayMs = Math.max(0, opts.delayMs || 0)
    const dist = Math.max(0, opts.distance || 12)
    const dir = opts.direction || 'up'
    const overshoot = Number.isFinite(opts.overshoot) ? opts.overshoot : 1.5
    const bounce = Number.isFinite(opts.bounce) ? opts.bounce : 1.2
    const ease = opts.ease || `back.out(${overshoot})`
    const elasticEase = `elastic.out(${bounce},0.55)`
    const useElastic = opts.elastic === true
    const actualEase = useElastic ? elasticEase : ease

    if (!enabled || !gsap) {
      el.style.opacity = '1'
      el.style.filter = ''
      el.style.transform = ''
      return Promise.resolve()
    }

    let x = 0
    let y = 0
    if (dir === 'down') y = -dist
    else if (dir === 'left') x = dist
    else if (dir === 'right') x = -dist
    else y = dist

    gsap.set(el, { opacity: 0, x, y })
    return new Promise(resolve => {
      gsap.to(el, {
        opacity: 1,
        x: 0,
        y: 0,
        duration: durationMs / 1000,
        delay: delayMs / 1000,
        ease: actualEase,
        overwrite: true,
        onComplete: () => {
          try { gsap.set(el, { clearProps: 'opacity,filter,transform' }) } catch {}
          resolve()
        }
      })
    })
  }

  class MotionFade extends HTMLElement {
    connectedCallback() {
      const dur = numAttr(this, 'duration', null)
      const delay = numAttr(this, 'delay', 0)
      const ease = strAttr(this, 'ease', 'power3.out')
      requestAnimationFrame(() => {
        fadeIn(this, { durationMs: dur || undefined, delayMs: delay, ease })
      })
    }
  }

  class MotionSlide extends HTMLElement {
    connectedCallback() {
      const dur = numAttr(this, 'duration', null)
      const delay = numAttr(this, 'delay', 0)
      const dir = strAttr(this, 'direction', 'up')
      const dist = numAttr(this, 'distance', 12)
      const overshoot = numAttr(this, 'overshoot', 1.5)
      const bounce = numAttr(this, 'bounce', 1.2)
      const elastic = strAttr(this, 'elastic', '') === 'true'
      requestAnimationFrame(() => {
        slideIn(this, { durationMs: dur || undefined, delayMs: delay, direction: dir, distance: dist, overshoot, bounce, elastic })
      })
    }
  }

  function defineSafe(name, ctor) {
    try {
      if (!customElements.get(name)) customElements.define(name, ctor)
    } catch {}
  }

  function init() {
    defineSafe('motion-fade', MotionFade)
    defineSafe('motion-slide', MotionSlide)
    window.Motion = {
      fadeIn,
      slideIn
    }
  }

  if (typeof window !== 'undefined') {
    if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', init)
    else init()
  }
})()
