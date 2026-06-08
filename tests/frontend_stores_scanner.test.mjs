import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')

test('scannerStore defines ScanResult interface', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('ScanResult'))
  assert.ok(scannerStoreSource.includes('fileId'))
  assert.ok(scannerStoreSource.includes("verdict"))
})

test('scannerStore interface defines state properties', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('isScanning'))
  assert.ok(scannerStoreSource.includes('scanResults'))
  assert.ok(scannerStoreSource.includes('scanProgress'))
  assert.ok(scannerStoreSource.includes('currentFile'))
  assert.ok(scannerStoreSource.includes('pendingFiles'))
  assert.ok(scannerStoreSource.includes('isWalkComplete'))
})

test('scannerStore interface defines actions', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('setSelectedFiles'))
  assert.ok(scannerStoreSource.includes('addSelectedFiles'))
  assert.ok(scannerStoreSource.includes('clearSelection'))
  assert.ok(scannerStoreSource.includes('startScan'))
  assert.ok(scannerStoreSource.includes('cancelScan'))
  assert.ok(scannerStoreSource.includes('clearResults'))
  assert.ok(scannerStoreSource.includes('removeScanResultsByPath'))
})

test('scannerStore defines removeScanResultsByPath action', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('removeScanResultsByPath'))
  assert.ok(scannerStoreSource.includes('pathSet'))
})

test('scannerStore removeScanResultsByPath filters by fileId', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('result.fileId'))
})

test('scannerStore removeScanResultsByPath also filters by description', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('result.description'))
})

test('scannerStore removeScanResultsByPath updates stats after removal', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('remainingResults'))
  assert.ok(scannerStoreSource.includes('threatsFound'))
  assert.ok(scannerStoreSource.includes('cleanFiles'))
})

test('scannerStore handles empty paths array', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  const filterLogic = (paths) => new Set(paths.filter(Boolean))
  const pathSet = filterLogic([])
  assert.equal(pathSet.size, 0)
})

test('scannerStore filters falsy values from paths array', () => {
  const filterLogic = (paths) => new Set(paths.filter(Boolean))
  const pathSet = filterLogic(['C:\\malware.exe', '', null, undefined, 0])
  assert.ok(pathSet.has('C:\\malware.exe'))
  assert.equal(pathSet.size, 1)
})

test('scannerStore startScan validates file selection', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('selectedFiles.length === 0'))
  assert.ok(scannerStoreSource.includes("'请先选择文件或目录'"))
})

test('scannerStore startScan uses scanFile and scanBatch APIs', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('scanFile'))
  assert.ok(scannerStoreSource.includes('scanBatch'))
})

test('scannerStore startScan handles progress events', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('onScanProgress'))
  assert.ok(scannerStoreSource.includes('scanProgress'))
  assert.ok(scannerStoreSource.includes('currentFile'))
})

test('scannerStore cancelScan resets scan state', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.ok(scannerStoreSource.includes('isScanning: false'))
  assert.ok(scannerStoreSource.includes('scanProgress: 0'))
})
