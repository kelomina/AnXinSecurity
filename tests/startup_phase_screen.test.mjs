import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')
const appSource = readFileSync(resolve(projectRoot, 'src/App.tsx'), 'utf8')
const splashScreenSource = readFileSync(resolve(projectRoot, 'src/components/SplashScreen.tsx'), 'utf8')
const snapshotApiSource = readFileSync(resolve(projectRoot, 'src/api/snapshot.ts'), 'utf8')
const zhI18nSource = readFileSync(resolve(projectRoot, 'config/i18n/zh-CN.json'), 'utf8')
const enI18nSource = readFileSync(resolve(projectRoot, 'config/i18n/en-US.json'), 'utf8')
const i18nStoreSource = readFileSync(resolve(projectRoot, 'src/stores/i18nStore.ts'), 'utf8')

test('startup phase screen consumes real snapshot progress and result events', () => {
  assert.match(snapshotApiSource, /export interface SnapshotProgressEvent/)
  assert.match(snapshotApiSource, /listen<SnapshotProgressEvent>\('snapshot-progress'/)
  assert.match(snapshotApiSource, /listen<SnapshotResult>\('snapshot-result'/)
  assert.match(appSource, /import \{ onSnapshotProgress, onSnapshotResult \} from '\.\/api\/snapshot'/)
  assert.match(appSource, /onSnapshotProgress\(\(progress\) => \{/)
  assert.match(appSource, /const percent = total > 0 \? \(current \/ total\) \* 100 : null/)
  assert.match(appSource, /setPhaseStatus\('snapshot', 'active'\)/)
  assert.match(appSource, /onSnapshotResult\(\(result\) => \{/)
  assert.match(appSource, /result\.deepScanCompleted \|\|[\s\S]*result\.deepScanPendingModules <= 0 && result\.deepScanPendingProcesses <= 0/)
  assert.match(appSource, /setPhaseStatus\('snapshot', 'complete'\)/)
  assert.match(appSource, /setPhaseStatus\('snapshot', 'warning'\)/)
  assert.match(appSource, /splash_status_pending_checks/)
  assert.match(appSource, /setSnapshotSummary\(\{/)
  assert.match(appSource, /baselineComplete: result\.baselineComplete/)
  assert.match(appSource, /deepScanPendingModules: Math\.max\(0, result\.deepScanPendingModules \|\| 0\)/)
  assert.match(appSource, /deepScanPendingProcesses: Math\.max\(0, result\.deepScanPendingProcesses \|\| 0\)/)
  assert.match(appSource, /result\.deepScanPendingModules <= 0 && result\.deepScanPendingProcesses <= 0/)
  assert.match(appSource, /snapshotProgress=\{snapshotProgress\}/)
  assert.match(appSource, /snapshotCurrent=\{snapshotCurrent\}/)
  assert.match(appSource, /snapshotTotal=\{snapshotTotal\}/)
  assert.match(appSource, /snapshotSummary=\{snapshotSummary\}/)
})

test('startup phase page renders a transparent trusted-environment checklist', () => {
  assert.match(splashScreenSource, /export type StartupPhaseStatus = 'pending' \| 'active' \| 'complete' \| 'warning' \| 'error'/)
  assert.match(splashScreenSource, /export interface StartupPhaseItem/)
  assert.match(splashScreenSource, /export interface StartupSnapshotSummary/)
  assert.match(splashScreenSource, /phases\.map\(\(phase\) =>/)
  assert.match(splashScreenSource, /phase\.detailKey/)
  assert.match(splashScreenSource, /data-status=\{phase\.status\}/)
  assert.match(splashScreenSource, /splash_snapshot_counter/)
  assert.match(splashScreenSource, /splash_security_note/)
  assert.match(splashScreenSource, /splash-summary-grid/)
  assert.match(splashScreenSource, /splash_summary_deep_pending/)
  assert.match(splashScreenSource, /deepScanPendingModules \+ snapshotSummary\.deepScanPendingProcesses/)
  assert.match(splashScreenSource, /unknownProcesses \+ snapshotSummary\.unknownModules/)
  assert.match(splashScreenSource, /maliciousProcesses \+ snapshotSummary\.maliciousModules/)
  assert.match(splashScreenSource, /Math\.round\(visibleProgress\)/)
  assert.doesNotMatch(splashScreenSource, /已可信|trusted baseline ready/i)
})

test('startup phase text is available in zh-CN, en-US, and built-in fallback', () => {
  const requiredKeys = [
    'splash_stage_label',
    'splash_stage_title',
    'splash_overall_progress',
    'splash_snapshot_waiting',
    'splash_snapshot_counter',
    'splash_security_note',
    'splash_phase_status_active',
    'splash_phase_status_warning',
    'splash_summary_baseline',
    'splash_summary_deep_pending',
    'splash_summary_unknown_value',
    'splash_summary_threats_value',
    'splash_summary_waiting',
    'splash_status_snapshot',
    'splash_phase_protection',
    'splash_phase_snapshot',
    'splash_status_pending_checks',
    'splash_phase_ready_detail',
  ]

  for (const key of requiredKeys) {
    assert.match(zhI18nSource, new RegExp(`"${key}"`))
    assert.match(enI18nSource, new RegExp(`"${key}"`))
    assert.match(i18nStoreSource, new RegExp(`${key}:`))
  }

  assert.match(zhI18nSource, /未完成检查不会被标记为可信/)
  assert.match(enI18nSource, /Pending checks are not marked trusted/)
})
