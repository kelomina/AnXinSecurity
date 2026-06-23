import React from 'react'
import { useConfigStore } from '../stores/configStore'
import { useI18nStore } from '../stores/i18nStore'
import { LayoutDashboard, Search, ShieldAlert, Activity, Settings } from 'lucide-react'
import { makeStyles, shorthands, tokens } from '@fluentui/react-components'

const useStyles = makeStyles({
  sidebar: {
    gridRow: '2',
    gridColumn: '1',
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.borderRight('1px', 'solid', tokens.colorNeutralStroke2),
    ...shorthands.padding('8px', '0'),
    overflowY: 'auto',
    backgroundColor: tokens.colorNeutralBackground2,
  },
  navList: {
    listStyle: 'none',
    flex: 1,
    ...shorthands.padding('8px', '0'),
  },
  navItem: {
    height: '44px',
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('12px'),
    ...shorthands.padding('0', '16px'),
    ...shorthands.margin('2px', '8px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    cursor: 'pointer',
    color: tokens.colorNeutralForeground2,
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightRegular,
    transitionProperty: 'all',
    transitionDuration: tokens.durationNormal,
    transitionTimingFunction: tokens.curveEasyEase,
    position: 'relative',
    background: 'none',
    ...shorthands.border('none'),
    width: 'calc(100% - 16px)',
    textAlign: 'left',
    ':hover': {
      backgroundColor: tokens.colorNeutralBackground1Hover,
      color: tokens.colorNeutralForeground1,
    },
    ':focus-visible': {
      outlineStyle: 'solid',
      outlineWidth: '2px',
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: '-2px',
    },
  },
  navItemActive: {
    backgroundColor: tokens.colorBrandBackground2,
    color: tokens.colorBrandForeground1,
    fontWeight: tokens.fontWeightSemibold,
    '::before': {
      content: '""',
      position: 'absolute',
      left: '-8px',
      top: '50%',
      transform: 'translateY(-50%)',
      width: '3px',
      height: '24px',
      backgroundColor: tokens.colorBrandForeground1,
      ...shorthands.borderRadius('0', '2px', '2px', '0'),
    },
  },
  navItemIcon: {
    flexShrink: 0,
  },
  sidebarFooter: {
    ...shorthands.padding('12px', '24px'),
    fontSize: '11px',
    color: tokens.colorNeutralForeground4,
    opacity: 0.6,
  },
})

const Sidebar: React.FC = () => {
  const { currentPage, setCurrentPage } = useConfigStore()
  const { t } = useI18nStore()
  const styles = useStyles()

  const menuItems = [
    { id: 'overview', labelKey: 'nav_overview', icon: LayoutDashboard },
    { id: 'scan', labelKey: 'nav_scan', icon: Search },
    { id: 'quarantine', labelKey: 'nav_quarantine', icon: ShieldAlert },
    { id: 'behavior', labelKey: 'nav_behavior', icon: Activity },
    { id: 'settings', labelKey: 'nav_settings', icon: Settings },
  ]

  return (
    <aside className={styles.sidebar}>
      <ul className={styles.navList}>
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = currentPage === item.id

          return (
            <li
              key={item.id}
              className={`${styles.navItem} ${isActive ? styles.navItemActive : ''}`}
              onClick={() => setCurrentPage(item.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  setCurrentPage(item.id)
                }
              }}
            >
              <Icon size={20} className={styles.navItemIcon} />
              <span>{t(item.labelKey)}</span>
            </li>
          )
        })}
      </ul>
      <div className={styles.sidebarFooter}>
        v1.0.0 (Prototype)
      </div>
    </aside>
  )
}

export default Sidebar
