import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, ShieldOff, X } from 'lucide-react'

interface InterceptionModalProps {
  isOpen: boolean
  onClose: () => void
  onAllow: () => void
  onBlock: () => void
  title: string
  message: string
  processName: string
  riskLevel: 'high' | 'medium' | 'low'
  filePath?: string
}

const InterceptionModal: React.FC<InterceptionModalProps> = ({
  isOpen, onClose, onAllow, onBlock, title, message, processName, riskLevel, filePath
}) => {
  const riskColors = {
    high: { bg: 'rgba(255,77,79,0.15)', text: '#ff4d4f', label: '高风险' },
    medium: { bg: 'rgba(255,169,64,0.15)', text: '#ffa940', label: '中风险' },
    low: { bg: 'rgba(82,196,26,0.15)', text: '#52c41a', label: '低风险' },
  }

  const riskStyle = riskColors[riskLevel]

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="modal-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            className="modal-surface"
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: '520px' }}
          >
            <div className="modal-header">
              <div className="modal-icon" style={{ backgroundColor: riskStyle.bg }}>
                {riskLevel === 'high' ? (
                  <ShieldOff size={24} color={riskStyle.text} />
                ) : (
                  <AlertTriangle size={24} color={riskStyle.text} />
                )}
              </div>
              <h3 style={{ color: riskStyle.text }}>{title}</h3>
              <button className="modal-close" onClick={onClose}>
                <X size={18} />
              </button>
            </div>

            <div className="modal-body">
              <p className="modal-message">{message}</p>

              <div style={{
                backgroundColor: 'var(--bg-tertiary)',
                borderRadius: '8px',
                padding: '12px',
                margin: '12px 0',
              }}>
                <div className="modal-detail">
                  <span className="detail-label">进程:</span>
                  <span className="detail-value" style={{ fontWeight: 600 }}>{processName}</span>
                </div>
                {filePath && (
                  <div className="modal-detail">
                    <span className="detail-label">路径:</span>
                    <span className="detail-value" style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                      {filePath}
                    </span>
                  </div>
                )}
                <div className={`risk-badge risk-${riskLevel}`} style={{
                  display: 'inline-block',
                  marginTop: '8px',
                  backgroundColor: riskStyle.bg,
                  color: riskStyle.text,
                  padding: '4px 12px',
                  borderRadius: '12px',
                  fontSize: '12px',
                  fontWeight: 600,
                }}>
                  {riskStyle.label}
                </div>
              </div>
            </div>

            <div className="modal-actions" style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
              <button className="btn btn-outline-secondary" onClick={onBlock}>
                阻止进程
              </button>
              <button className="btn btn-primary" onClick={onAllow}>
                允许运行
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default InterceptionModal
