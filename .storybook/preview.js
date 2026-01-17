import 'bootstrap/dist/css/bootstrap.min.css'
import '../src/renderer/styles.css'

import { gsap } from 'gsap'
import lottie from 'lottie-web'

window.gsap = gsap
window.lottie = lottie

import '../src/renderer/motion/motion_components.js'

export const parameters = {
  layout: 'fullscreen'
}

