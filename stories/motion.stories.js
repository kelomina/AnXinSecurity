export default {
  title: 'Motion'
}

import loaderData from '../src/renderer/assets/lottie/particle_loader.json'

export const PressHover = {
  render: () => {
    const root = document.createElement('div')
    root.style.padding = '16px'
    root.innerHTML = `
      <div class="d-flex gap-2 flex-wrap align-items-center">
        <button class="btn btn-primary">Primary</button>
        <button class="btn btn-outline-primary">Outline</button>
        <button class="btn btn-danger">Danger</button>
      </div>
      <div class="mt-3 card" style="max-width: 520px;">
        <h5 class="mb-1">Card</h5>
        <div class="text-muted small">Hover/press 反馈与光效描边</div>
      </div>
    `
    return root
  }
}

export const LottieLoader = {
  render: () => {
    const root = document.createElement('div')
    root.style.padding = '16px'
    root.innerHTML = `
      <div class="card" style="max-width: 520px;">
        <h5 class="mb-2">Lottie Loader</h5>
        <div class="d-flex justify-content-center align-items-center" style="height: 120px;">
          <div id="lottie-demo" style="width: 84px; height: 84px;"></div>
        </div>
      </div>
    `
    const container = root.querySelector('#lottie-demo')
    try {
      if (container && window.lottie) {
        window.lottie.loadAnimation({
          container,
          renderer: 'svg',
          loop: true,
          autoplay: true,
          animationData: loaderData
        })
      }
    } catch {}
    return root
  }
}

export const MotionFade = {
  render: () => {
    const root = document.createElement('div')
    root.style.padding = '16px'
    root.innerHTML = `
      <motion-fade>
        <div class="card" style="max-width: 520px;">
          <h5 class="mb-1">motion-fade</h5>
          <div class="text-muted small">进入时淡入</div>
        </div>
      </motion-fade>
    `
    return root
  }
}

export const MotionSlideElastic = {
  render: () => {
    const root = document.createElement('div')
    root.style.padding = '16px'
    root.innerHTML = `
      <motion-slide direction="up" distance="18" elastic="true" bounce="1.2">
        <div class="card" style="max-width: 520px;">
          <h5 class="mb-1">motion-slide</h5>
          <div class="text-muted small">弹性（bounce=1.2）与 overshoot</div>
        </div>
      </motion-slide>
    `
    return root
  }
}

export const PageTransitionDemo = {
  render: () => {
    const root = document.createElement('div')
    root.style.padding = '16px'
    root.innerHTML = `
      <div class="d-flex gap-2 mb-3">
        <button class="btn btn-outline-light btn-sm" id="btn-a">View A</button>
        <button class="btn btn-outline-light btn-sm" id="btn-b">View B</button>
      </div>
      <div id="stage" style="position: relative; perspective: 900px; height: 180px;">
        <div id="view-a" class="card" style="position:absolute; inset:0;">
          <h5 class="mb-1">A</h5>
          <div class="text-muted small">3D + blur 过渡示意</div>
        </div>
        <div id="view-b" class="card" style="position:absolute; inset:0; display:none;">
          <h5 class="mb-1">B</h5>
          <div class="text-muted small">3D + blur 过渡示意</div>
        </div>
      </div>
    `
    const a = root.querySelector('#view-a')
    const b = root.querySelector('#view-b')
    const btnA = root.querySelector('#btn-a')
    const btnB = root.querySelector('#btn-b')

    const animate = (from, to) => {
      if (!window.gsap) return
      to.style.display = 'block'
      const blur = 10
      window.gsap.set(from, { opacity: 1, y: 0, z: 0, filter: 'blur(0px)' })
      window.gsap.set(to, { opacity: 0, y: 10, z: 120, filter: `blur(${blur}px)` })
      const tl = window.gsap.timeline({
        defaults: { duration: 0.38, overwrite: true },
        onComplete: () => {
          from.style.display = 'none'
          try {
            window.gsap.set(from, { clearProps: 'opacity,transform,filter' })
            window.gsap.set(to, { clearProps: 'opacity,transform,filter' })
          } catch {}
        }
      })
      tl.to(from, { opacity: 0, y: -6, z: -120, filter: `blur(${blur}px)`, ease: 'power2.inOut' }, 0)
      tl.to(to, { opacity: 1, y: 0, z: 0, filter: 'blur(0px)', ease: 'power3.out' }, 0.04)
    }

    btnA.onclick = () => animate(b, a)
    btnB.onclick = () => animate(a, b)

    return root
  }
}
