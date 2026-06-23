/**
 * Fluent 2 按钮包装器
 * Fluent 2 Button wrapper component
 *
 * 提供符合Fluent 2设计规范的按钮，包含图标支持
 */
import React from 'react'
import { Button, ButtonProps, makeStyles, shorthands, tokens } from '@fluentui/react-components'

const useStyles = makeStyles({
  buttonWithIcon: {
    ...shorthands.gap('8px'),
  },
  primaryButton: {
    backgroundColor: tokens.colorBrandBackground,
    color: tokens.colorNeutralForegroundOnBrand,
    ':hover': {
      backgroundColor: tokens.colorBrandBackgroundHover,
    },
    ':active': {
      backgroundColor: tokens.colorBrandBackgroundPressed,
    },
  },
  dangerButton: {
    backgroundColor: tokens.colorPaletteRedBackground3,
    color: '#fff',
    ':hover': {
      backgroundColor: tokens.colorPaletteRedBackground2,
    },
  },
  successButton: {
    backgroundColor: tokens.colorPaletteGreenBackground3,
    color: '#fff',
    ':hover': {
      backgroundColor: tokens.colorPaletteGreenBackground2,
    },
  },
  warningButton: {
    backgroundColor: tokens.colorPaletteYellowBackground3,
    color: '#fff',
    ':hover': {
      backgroundColor: tokens.colorPaletteYellowBackground2,
    },
  },
})

export interface CustomButtonProps extends Omit<ButtonProps, 'appearance'> {
  appearance?: 'primary' | 'secondary' | 'subtle' | 'transparent' | 'danger' | 'success' | 'warning' | 'outline-primary' | 'outline-danger'
}

export const FluentButton: React.FC<CustomButtonProps> = ({
  appearance = 'primary',
  icon,
  children,
  className,
  ...props
}) => {
  const styles = useStyles()

  // Map custom appearances to Fluent appearances and styles
  let fluentAppearance: ButtonProps['appearance'] = 'primary'
  let customClassName = className

  switch (appearance) {
    case 'danger':
      fluentAppearance = 'primary'
      customClassName = `${styles.dangerButton} ${className || ''}`
      break
    case 'success':
      fluentAppearance = 'primary'
      customClassName = `${styles.successButton} ${className || ''}`
      break
    case 'warning':
      fluentAppearance = 'primary'
      customClassName = `${styles.warningButton} ${className || ''}`
      break
    case 'outline-primary':
      fluentAppearance = 'outline'
      break
    case 'outline-danger':
      fluentAppearance = 'outline'
      customClassName = `${className || ''}`
      break
    case 'primary':
      fluentAppearance = 'primary'
      customClassName = `${styles.primaryButton} ${className || ''}`
      break
    default:
      fluentAppearance = appearance as ButtonProps['appearance']
  }

  return (
    <Button
      {...(props as any)}
      appearance={fluentAppearance}
      className={`${styles.buttonWithIcon} ${customClassName || ''}`}
      icon={icon}
    >
      {children}
    </Button>
  )
}

export default FluentButton
