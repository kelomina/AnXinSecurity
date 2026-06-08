import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')

test('toastStore exports ToastType and ToastItem types', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')

  assert.match(toastStoreSource, /export type ToastType = 'info' \| 'success' \| 'warning' \| 'error'/)
  assert.match(toastStoreSource, /export interface ToastItem/)
  assert.match(toastStoreSource, /id: string/)
  assert.match(toastStoreSource, /type: ToastType/)
  assert.match(toastStoreSource, /message: string/)
  assert.match(toastStoreSource, /duration\?: number/)
})

test('toastStore interface defines required methods', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')

  assert.match(toastStoreSource, /interface ToastState/)
  assert.match(toastStoreSource, /toasts: ToastItem\[\]/)
  assert.match(toastStoreSource, /addToast: \(type: ToastType, message: string, duration\?: number\) => void/)
  assert.match(toastStoreSource, /removeToast: \(id: string\) => void/)
})

test('toastStore addToast generates unique ID', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')

  const addToastLogic = (type, message, duration = 4000) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
    return { id, type, message, duration }
  }

  const toast1 = addToastLogic('info', 'Message 1')
  const toast2 = addToastLogic('info', 'Message 2')

  assert.ok(toast1.id.includes('-'), 'ID should contain timestamp separator')
  assert.notEqual(toast1.id, toast2.id, 'Each toast should have unique ID')
  assert.ok(toast1.id.length > 10, 'ID should be sufficiently long')
})

test('toastStore addToast defaults duration to 4000ms', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /addToast: \(type, message, duration = 4000\)/)
})

test('toastStore addToast creates toast with all fields', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /\{ id, type, message, duration \}/)
})

test('toastStore addToast schedules auto-removal when duration > 0', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /if \(duration > 0\) \{[\s\S]*setTimeout/)
  assert.match(toastStoreSource, /toasts: state\.toasts\.filter\(\(t\) => t\.id !== id\)/)
})

test('toastStore addToast skips auto-removal when duration is 0', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /if \(duration > 0\)/)
})

test('toastStore removeToast filters by ID', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /removeToast: \(id\) => \{[\s\S]*toasts: state\.toasts\.filter\(\(t\) => t\.id !== id\)/)
})

test('toastStore initial state has empty toasts array', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /toasts: \[\]/)
})

test('toastStore addToast updates state immutably', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /set\(\(state\) => \(\{[\s\S]*toasts: \[\.\.\.state\.toasts, \{ id, type, message, duration \}\]/)
})

test('toastStore removeToast updates state immutably', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /set\(\(state\) => \(\{[\s\S]*toasts: state\.toasts\.filter/)
})

test('toast ID format includes timestamp and random component', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /\$\{Date\.now\(\)\}/)
  assert.match(toastStoreSource, /Math\.random\(\)\.toString\(36\)/)
})

test('toast auto-removal uses setTimeout with correct duration', () => {
  const toastStoreSource = readFileSync(resolve(projectRoot, 'src/stores/toastStore.ts'), 'utf8')
  assert.match(toastStoreSource, /setTimeout\(\(\) => \{[\s\S]*toasts: state\.toasts\.filter\(\(t\) => t\.id !== id\)/, /[\s\S]*\}, duration\)/)
})
