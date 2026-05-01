/**
 * 启动画面组件
 * Splash screen component
 *
 * 应用启动时显示的品牌加载画面，支持进度状态更新。
 * Branded loading screen displayed during application startup, supports progress status updates.
 *
 * 调用方：App.tsx (初始化阶段)
 * Called by: App.tsx (during initialization phase)
 *
 * 中文关键词：启动画面，加载画面，品牌展示，启动动画
 * English keywords: splash screen, loading screen, brand display, startup animation
 */
import React, { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

interface SplashScreenProps {
  isVisible: boolean
  statusText?: string
}

const SplashScreen: React.FC<SplashScreenProps> = ({ isVisible, statusText }) => {
  const [dots, setDots] = useState(0)

  useEffect(() => {
    if (!isVisible) return
    const interval = setInterval(() => {
      setDots((prev) => (prev + 1) % 4)
    }, 500)
    return () => clearInterval(interval)
  }, [isVisible])

  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          className="splash-overlay"
          initial={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.4 }}
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            zIndex: 9999,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            backgroundColor: 'var(--bg-primary, #0d1117)',
            backdropFilter: 'blur(80px)',
          }}
        >
          {/* Logo / 品牌标识 */}
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2, duration: 0.6, ease: 'easeOut' }}
            style={{ marginBottom: '32px' }}
          >
            <div
              style={{
                width: '80px',
                height: '80px',
                borderRadius: '20px',
                background: 'linear-gradient(135deg, var(--brand-color, #4CA2FF), var(--brand-color-secondary, #7C5CFC))',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '36px',
                color: '#fff',
                fontWeight: 700,
                boxShadow: '0 8px 32px rgba(76, 162, 255, 0.3)',
              }}
            >
              AX
            </div>
          </motion.div>

          {/* 品牌名称 / Brand name */}
          <motion.h1
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5, duration: 0.5 }}
            style={{
              fontSize: '28px',
              fontWeight: 700,
              color: 'var(--text-primary, #e6edf3)',
              marginBottom: '12px',
              letterSpacing: '0.5px',
            }}
          >
            AnXin Security
          </motion.h1>

          {/* 加载状态 / Loading status */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8 }}
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '16px',
              marginTop: '16px',
            }}
          >
            {/* 进度指示器 / Progress indicator */}
            <div
              style={{
                width: '200px',
                height: '4px',
                backgroundColor: 'var(--bg-tertiary, rgba(255,255,255,0.1))',
                borderRadius: '2px',
                overflow: 'hidden',
              }}
            >
              <motion.div
                initial={{ width: '0%' }}
                animate={{
                  width: ['0%', '30%', '60%', '85%', '95%'],
                }}
                transition={{
                  duration: 3,
                  repeat: Infinity,
                  ease: 'easeInOut',
                }}
                style={{
                  height: '100%',
                  backgroundColor: 'var(--brand-color, #4CA2FF)',
                  borderRadius: '2px',
                }}
              />
            </div>

            {/* 状态文本 / Status text */}
            <p
              style={{
                fontSize: '14px',
                color: 'var(--text-tertiary, #8b949e)',
                margin: 0,
              }}
            >
              {statusText || '正在初始化安全服务'}
              <span style={{ display: 'inline-block', width: '24px', textAlign: 'left' }}>
                {'.'.repeat(dots)}
              </span>
            </p>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default SplashScreen
