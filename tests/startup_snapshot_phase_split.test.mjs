import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')
const snapshotServiceSource = readFileSync(
  resolve(projectRoot, 'src-tauri/src/services/snapshot_service.rs'),
  'utf8',
)
const snapshotCommandSource = readFileSync(
  resolve(projectRoot, 'src-tauri/src/commands/snapshot.rs'),
  'utf8',
)
const snapshotApiSource = readFileSync(resolve(projectRoot, 'src/api/snapshot.ts'), 'utf8')

test('startup snapshot emits baseline result before background module deep checks', () => {
  const resultBuildIndex = snapshotServiceSource.indexOf('let result = SnapshotResult {')
  const emitIndex = snapshotServiceSource.indexOf('app_handle.emit("snapshot-result", &result)', resultBuildIndex)
  const spawnIndex = snapshotServiceSource.indexOf('spawn_startup_module_deep_checks(StartupModuleDeepCheckContext', emitIndex)
  const moduleBatchIndex = snapshotServiceSource.indexOf('verify_module_targets_concurrent(', spawnIndex)

  assert.ok(resultBuildIndex >= 0, 'baseline result should be built')
  assert.ok(emitIndex > resultBuildIndex, 'baseline result should be emitted')
  assert.ok(spawnIndex > emitIndex, 'module deep checks should start after baseline emit')
  assert.ok(moduleBatchIndex > spawnIndex, 'module signature batch should live in the background path')
})

test('pending deep module checks remain unknown until background completion', () => {
  assert.match(snapshotServiceSource, /deep_scan_pending_modules = all_modules_requiring_signature\.len\(\) as u32/)
  assert.match(snapshotServiceSource, /deep_scan_pending_processes = deferred_process_module_checks\.len\(\) as u32/)
  assert.match(snapshotServiceSource, /unknown_modules = unknown_modules\.saturating_add\(deep_scan_pending_modules\)/)
  assert.match(snapshotServiceSource, /deep_scan_completed,/)
  assert.match(snapshotServiceSource, /deep_scan_completed =[\s\S]*deep_scan_pending_processes == 0 && deep_scan_pending_modules == 0/)
  assert.match(snapshotServiceSource, /result\.unknown_modules[\s\S]*\.saturating_sub\(pending_modules\)[\s\S]*\.saturating_add\(deferred_module_target_unknown_delta\)[\s\S]*\.saturating_add\(unknown_modules_delta\)/)
  assert.match(snapshotServiceSource, /result\.unknown_processes[\s\S]*\.saturating_sub\(pending_processes\)[\s\S]*\.saturating_add\(deferred_process_unknown_delta\)/)
  assert.match(snapshotServiceSource, /result\.deep_scan_completed = true/)
  assert.match(snapshotServiceSource, /result\.deep_scan_pending_modules = 0/)
  assert.match(snapshotServiceSource, /result\.deep_scan_pending_processes = 0/)
  assert.doesNotMatch(snapshotServiceSource, /newly_pending_modules/)
})

test('deferred deep checks only clear unknown items after verification succeeds', () => {
  assert.match(snapshotServiceSource, /let mut deferred_module_target_unknown_delta: u32 = 0/)
  assert.match(snapshotServiceSource, /deferred_module_enumeration_failures[\s\S]*deferred_module_target_unknown_delta[\s\S]*\.saturating_add\(1\)/)
  assert.match(snapshotServiceSource, /module_target\.skip_reason\.is_some\(\) \{[\s\S]*deferred_module_target_unknown_delta[\s\S]*\.saturating_add\(1\)/)
  assert.match(snapshotServiceSource, /let module_signature_timed_out = module_verdict\.timed_out/)
  assert.match(snapshotServiceSource, /let mut module_should_remain_unknown = module_signature_timed_out/)
  assert.match(snapshotServiceSource, /StartupScanOutcome::Failed[\s\S]*module_should_remain_unknown = true/)
  assert.match(snapshotServiceSource, /module_signature_untrusted && !module_scan_was_malicious[\s\S]*module_should_remain_unknown = true/)
  assert.match(snapshotServiceSource, /if module_should_remain_unknown \{[\s\S]*unknown_modules_delta = unknown_modules_delta\.saturating_add\(1\)/)
})

test('non-critical trusted process module checks move to background without trusting pending work', () => {
  const deferDecisionIndex = snapshotServiceSource.indexOf('should_defer_startup_process_module_checks(')
  const foregroundModuleEnumerationIndex = snapshotServiceSource.indexOf(
    'let module_info = match enumerate_process_module_info_with_timeout',
    deferDecisionIndex,
  )
  const resultBuildIndex = snapshotServiceSource.indexOf('let result = SnapshotResult {')
  const spawnIndex = snapshotServiceSource.indexOf('spawn_startup_module_deep_checks(StartupModuleDeepCheckContext', resultBuildIndex)

  assert.ok(deferDecisionIndex > 0, 'defer decision should exist in the foreground loop')
  assert.ok(foregroundModuleEnumerationIndex > deferDecisionIndex, 'foreground still supports priority module enumeration')
  assert.ok(resultBuildIndex > foregroundModuleEnumerationIndex, 'baseline result is emitted after priority checks')
  assert.ok(spawnIndex > resultBuildIndex, 'deferred process checks run only after baseline result')
  const deferredPushIndex = snapshotServiceSource.indexOf(
    'deferred_process_module_checks.push(StartupDeferredProcessModuleCheck',
    deferDecisionIndex,
  )
  const deferredBranchSnippet = snapshotServiceSource.slice(deferDecisionIndex, deferredPushIndex)
  assert.ok(deferredPushIndex > deferDecisionIndex)
  assert.match(snapshotServiceSource, /deferred_process_module_checks\.push\(StartupDeferredProcessModuleCheck/)
  assert.match(snapshotServiceSource, /unknown_processes \+= 1;[\s\S]*deferred_process_module_checks\.push/)
  assert.doesNotMatch(deferredBranchSnippet, /signed \+= 1/)
  assert.match(snapshotServiceSource, /matches!\(masquerade_verdict, MasqueradeVerdict::NotApplicable\)[\s\S]*&& process_path_scannable[\s\S]*&& process_is_trusted/)
  assert.match(snapshotServiceSource, /for deferred in deferred_processes/)
  assert.match(snapshotServiceSource, /detect_process_image_integrity_from_modules\(\s*deferred\.pid/)
  assert.match(snapshotServiceSource, /enqueue_process_image_integrity_interception\(/)
})

test('process main-file signatures are prefetched through bounded verification cache', () => {
  const prefetchIndex = snapshotServiceSource.indexOf('process_signature_prefetch_targets')
  const loopIndex = snapshotServiceSource.indexOf('for (i, proc_info) in processes.iter().enumerate()')

  assert.ok(prefetchIndex > 0, 'process signature prefetch should exist')
  assert.ok(loopIndex > prefetchIndex, 'prefetch should run before the foreground process loop consumes signatures')
  assert.match(snapshotServiceSource, /let process_signature_prefetch_targets: Vec<StartupModuleSignatureTarget> = processes/)
  assert.match(snapshotServiceSource, /target\.signature_cache_key\.is_none\(\)/)
  assert.match(snapshotServiceSource, /verify_module_targets_concurrent\(\s*trust\.clone\(\),\s*process_signature_prefetch_targets,\s*signature_verify_timeout,\s*signature_verify_concurrency/)
  assert.match(snapshotServiceSource, /verify_file_for_target_async\(\s*trust\.clone\(\),\s*&proc_info\.path/)
})

test('automatic signature verification concurrency follows logical processors', () => {
  assert.match(snapshotServiceSource, /const AUTO_STARTUP_SIGNATURE_VERIFY_CONCURRENCY: usize = 0/)
  assert.match(snapshotServiceSource, /fn resolve_startup_signature_verify_concurrency\(configured: usize\) -> usize/)
  assert.match(snapshotServiceSource, /if configured > 0 \{[\s\S]*return configured;/)
  assert.match(snapshotServiceSource, /std::thread::available_parallelism\(\)[\s\S]*parallelism\.get\(\)\.max\(1\)/)
  assert.match(snapshotServiceSource, /unwrap_or\(FALLBACK_STARTUP_SIGNATURE_VERIFY_CONCURRENCY\)/)
  assert.match(snapshotServiceSource, /signature_verify_concurrency: u32/)
  assert.match(snapshotServiceSource, /performance\.signature_verify_concurrency/)
  assert.match(snapshotServiceSource, /signatureConcurrency=\{\}/)
  assert.match(snapshotApiSource, /signatureVerifyConcurrency\?: number/)
})

test('snapshot status fields are exposed through backend empty result and frontend type', () => {
  for (const key of ['baseline_complete', 'deep_scan_completed', 'deep_scan_pending_modules', 'deep_scan_pending_processes']) {
    assert.match(snapshotCommandSource, new RegExp(`${key}:`))
  }

  for (const key of ['baselineComplete', 'deepScanCompleted', 'deepScanPendingModules', 'deepScanPendingProcesses']) {
    assert.match(snapshotApiSource, new RegExp(`${key}:`))
  }

  assert.match(snapshotApiSource, /baselineDurationMs\?: number/)
  assert.match(snapshotApiSource, /deepScanDurationMs\?: number/)
})
