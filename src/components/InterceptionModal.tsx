import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle, X } from 'lucide-react'

interface InterceptionModalProps {
  isOpen: boolean
  onClose: () => void
  onAllow: () => void
  onBlock: () => void
  title: string
  message: string
  processName: string
  riskLevel: 'high' | 'medium' | 'low'
}

const InterceptionModal: React.FC<InterceptionModalProps> = ({
  isOpen, onClose, onAllow, onBlock, title, message, processName, riskLevel
}) => {
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
          >
            <div className="modal-header">
              <div className="modal-icon">
                <AlertTriangle size={24} />
              </div>
              <h3>{title}</h3>
              <button className="modal-close" onClick={onClose}>
                <X size={18} />
              </button>
            </div>
            
            <div className="modal-body">
              <p className="modal-message">{message}</p>
              <div className="modal-detail">
                <span className="detail-label">进程:</span>
                <span className="detail-value">{processName}</span>
              </div>
              <div className={`risk-badge risk-${riskLevel}`}>
                风险等级: {riskLevel.toUpperCase()}
              </div>
            </div>
            
            <div className="modal-actions">
              <button className="btn btn-outline-secondary" onClick={onBlock}>
                阻止
              </button>
              <button className="btn btn-primary" onClick={onAllow}>
                允许
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

export default InterceptionModal
