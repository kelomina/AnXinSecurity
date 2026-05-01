import React from 'react'
import { useConfigStore } from '../stores/configStore'
import { LayoutDashboard, Search, ShieldAlert, Activity, Settings } from 'lucide-react'

const Sidebar: React.FC = () => {
  const { currentPage, setCurrentPage } = useConfigStore()

  const menuItems = [
    { id: 'overview', label: '概览', icon: LayoutDashboard },
    { id: 'scan', label: '扫描', icon: Search },
    { id: 'quarantine', label: '隔离区', icon: ShieldAlert },
    { id: 'behavior', label: 'EDR', icon: Activity },
    { id: 'settings', label: '设置', icon: Settings },
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <h2>AnXin Security</h2>
      </div>
      <nav className="sidebar-nav">
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = currentPage === item.id
          
          return (
            <button
              key={item.id}
              className={`nav-btn ${isActive ? 'active' : ''}`}
              onClick={() => setCurrentPage(item.id)}
            >
              <Icon size={20} className="nav-icon" />
              <span className="nav-label">{item.label}</span>
            </button>
          )
        })}
      </nav>
    </aside>
  )
}

export default Sidebar
