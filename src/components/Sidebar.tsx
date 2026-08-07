import React from 'react'
import { useConfigStore } from '../stores/configStore'
import { useI18nStore } from '../stores/i18nStore'
import { LayoutDashboard, Search, ShieldAlert, Activity, Firewall, Settings } from './icons'
import { Button, makeStyles, shorthands, tokens } from '@fluentui/react-components'

const useStyles = makeStyles({
  sidebar: {
    gridRow: '2',
    gridColumn: '1',
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.borderRight('1px', 'solid', tokens.colorNeutralStroke1),
    ...shorthands.padding('8px', '0'),
    overflowY: 'auto',
    backgroundColor: tokens.colorNeutralBackground1,
  },
  navList: {
    listStyle: 'none',
    flex: 1,
    ...shorthands.padding('0'),
    ...shorthands.margin('0'),
    display: 'flex',
    flexDirection: 'column',
    ...shorthands.gap('2px'),
  },
  navItemWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
    ...shorthands.margin('2px', '8px'),
    width: 'calc(100% - 16px)',
  },

  navItem: {
    height: '36px',
    display: 'flex',
    alignItems: 'center',
    ...shorthands.gap('10px'),
    ...shorthands.padding('8px', '16px'),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    cursor: 'pointer',
    color: tokens.colorNeutralForeground1,
    fontSize: tokens.fontSizeBase300,
    fontWeight: tokens.fontWeightRegular,
    transitionProperty: 'background, color',
    transitionDuration: tokens.durationFaster,
    transitionTimingFunction: tokens.curveEasyEase,
    width: '100%',
    justifyContent: 'flex-start',
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
    backgroundColor: `${tokens.colorBrandBackground2} !important`,
    color: `${tokens.colorBrandForeground1} !important`,
    fontWeight: tokens.fontWeightSemibold,
    ':hover': {
      backgroundColor: `${tokens.colorBrandBackground2} !important`,
      color: `${tokens.colorBrandForeground2} !important`,
    },
  },
  navItemIcon: {
    flexShrink: 0,
  },
  sidebarFooter: {
    ...shorthands.padding('8px', '16px'),
    fontSize: '11px',
    color: tokens.colorNeutralForeground3,
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
    { id: 'firewall', labelKey: 'nav_firewall', icon: Firewall },
    { id: 'settings', labelKey: 'nav_settings', icon: Settings },
  ]

  return (
    <aside className={styles.sidebar}>
      <nav aria-label={t('nav_main')} className={styles.navList}>
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = currentPage === item.id

          return (
            <div
              key={item.id}
              className={styles.navItemWrapper}
            >
              {isActive && (
                <div
                  style={{
                    position: 'absolute',
                    left: '0',
                    top: '6px',
                    bottom: '6px',
                    width: '3px',
                    backgroundColor: tokens.colorBrandStroke1,
                    borderRadius: '2px',
                    zIndex: 2,
                    pointerEvents: 'none',
                  }}
                />
              )}
              <Button
                appearance="subtle"
                className={`${styles.navItem} ${isActive ? styles.navItemActive : ''}`}
                onClick={() => setCurrentPage(item.id)}
                aria-current={isActive ? 'page' : undefined}
                icon={<Icon size={20} className={styles.navItemIcon} />}
              >
                <span>{t(item.labelKey)}</span>
              </Button>
            </div>
          )
        })}
      </nav>
      <div className={styles.sidebarFooter}>
        v1.0.0 (Prototype)
      </div>
    </aside>
  )
}

export default Sidebar
