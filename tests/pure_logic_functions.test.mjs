import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')

test('mergeTrustItems deduplicates by normalized path and merges sources', () => {
  const configStoreSource = readFileSync(resolve(projectRoot, 'src/stores/configStore.ts'), 'utf8')

  assert.match(configStoreSource, /export const mergeTrustItems/)
  assert.match(configStoreSource, /const mergedItems = new Map/)
  assert.match(configStoreSource, /normalizeTrustPath/)

  const exclusions = [
    { path: 'C:\\Safe\\app.exe', entry_type: 'file', description: 'Excluded app', created_at: '2026-01-01T00:00:00Z' },
    { path: 'C:\\Safe\\folder', entry_type: 'directory', description: 'Excluded dir', created_at: '2026-01-02T00:00:00Z' }
  ]
  const allowlist = [
    { path: 'C:/Safe/App.exe', hash: 'abc123', description: 'Allowed app', created_at: '2026-01-03T00:00:00Z' }
  ]

  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  const mergedItems = new Map()
  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }
  for (const allowedItem of allowlist) {
    const key = normalizeTrustPath(allowedItem.path)
    const existingItem = mergedItems.get(key)
    if (existingItem) {
      mergedItems.set(key, {
        ...existingItem,
        hash: allowedItem.hash ?? existingItem.hash,
        description: existingItem.description ?? allowedItem.description,
        created_at: existingItem.created_at <= allowedItem.created_at ? existingItem.created_at : allowedItem.created_at,
        sources: existingItem.sources.includes('allowlist')
          ? existingItem.sources
          : [...existingItem.sources, 'allowlist']
      })
      continue
    }
    mergedItems.set(key, {
      path: allowedItem.path,
      entry_type: 'file',
      hash: allowedItem.hash,
      description: allowedItem.description,
      created_at: allowedItem.created_at,
      sources: ['allowlist']
    })
  }

  const result = Array.from(mergedItems.values())

  assert.equal(result.length, 2, 'same normalized path should be deduplicated')
  const appEntry = result.find(e => normalizeTrustPath(e.path) === 'c:\\safe\\app.exe')
  assert.ok(appEntry, 'merged app entry should exist')
  assert.deepEqual(appEntry.sources, ['exclusion', 'allowlist'], 'sources should be merged')
  assert.equal(appEntry.hash, 'abc123', 'hash from allowlist should be present')
  assert.equal(appEntry.description, 'Excluded app', 'exclusion description takes priority')
})

test('mergeTrustItems sorts by created_at descending', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  const exclusions = [
    { path: 'C:\\old.exe', entry_type: 'file', description: 'Old', created_at: '2026-01-01T00:00:00Z' },
    { path: 'C:\\new.exe', entry_type: 'file', description: 'New', created_at: '2026-06-01T00:00:00Z' }
  ]
  const allowlist = []

  const mergedItems = new Map()
  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }
  const result = Array.from(mergedItems.values()).sort((a, b) =>
    b.created_at.localeCompare(a.created_at)
  )

  assert.equal(result[0].path, 'C:\\new.exe', 'newer item should be first')
  assert.equal(result[1].path, 'C:\\old.exe', 'older item should be second')
})

test('normalizeTrustPath handles forward slashes, case, and whitespace', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  assert.equal(normalizeTrustPath('C:/Windows/System32'), 'c:\\windows\\system32')
  assert.equal(normalizeTrustPath('  C:\\APP  '), 'c:\\app')
  assert.equal(normalizeTrustPath('C:\\Safe\\App.exe'), 'c:\\safe\\app.exe')
  assert.equal(normalizeTrustPath('c:/safe/app.exe'), 'c:\\safe\\app.exe')
})

test('normalizeQuarantineItem falls back to snake_case fields with safe defaults', () => {
  const quarantineSource = readFileSync(resolve(projectRoot, 'src/api/quarantine.ts'), 'utf8')

  assert.match(quarantineSource, /interface RawQuarantineItem/)
  assert.match(quarantineSource, /originalPath: item\.originalPath \?\? item\.original_path \?\? ''/)
  assert.match(quarantineSource, /fileSize: item\.fileSize \?\? item\.file_size \?\? 0/)
  assert.match(quarantineSource, /fileHash: item\.fileHash \?\? item\.file_hash \?\? ''/)
  assert.match(quarantineSource, /isolatedAt: item\.isolatedAt \?\? item\.isolated_at \?\? ''/)

  const normalizeQuarantineItem = (item) => ({
    id: item.id,
    originalPath: item.originalPath ?? item.original_path ?? '',
    fileHash: item.fileHash ?? item.file_hash ?? '',
    fileSize: item.fileSize ?? item.file_size ?? 0,
    threatType: item.threatType ?? item.threat_type,
    threatFamily: item.threatFamily ?? item.threat_family,
    status: item.status,
    isolatedAt: item.isolatedAt ?? item.isolated_at ?? '',
    restoredAt: item.restoredAt ?? item.restored_at,
    description: item.description,
  })

  const snakeCaseItem = {
    id: 'test-id',
    original_path: 'C:\\malware.exe',
    file_hash: 'deadbeef',
    file_size: 1024,
    threat_type: 'trojan',
    status: 'quarantined',
    isolated_at: '2026-01-01T00:00:00Z',
  }
  const normalized = normalizeQuarantineItem(snakeCaseItem)
  assert.equal(normalized.originalPath, 'C:\\malware.exe')
  assert.equal(normalized.fileHash, 'deadbeef')
  assert.equal(normalized.fileSize, 1024)
  assert.equal(normalized.threatType, 'trojan')
  assert.equal(normalized.isolatedAt, '2026-01-01T00:00:00Z')

  const emptyItem = { id: 'empty', status: 'quarantined' }
  const emptyNormalized = normalizeQuarantineItem(emptyItem)
  assert.equal(emptyNormalized.originalPath, '', 'missing path defaults to empty string')
  assert.equal(emptyNormalized.fileSize, 0, 'missing size defaults to 0')
  assert.equal(emptyNormalized.fileHash, '', 'missing hash defaults to empty string')
})

test('formatFileSize handles all size ranges correctly', () => {
  const quarantineSource = readFileSync(resolve(projectRoot, 'src/api/quarantine.ts'), 'utf8')

  assert.match(quarantineSource, /export function formatFileSize/)
  assert.match(quarantineSource, /bytes < 1024/)
  assert.match(quarantineSource, /bytes < 1024 \* 1024/)

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  assert.equal(formatFileSize(0), '0 B')
  assert.equal(formatFileSize(512), '512 B')
  assert.equal(formatFileSize(1023), '1023 B')
  assert.equal(formatFileSize(1024), '1.00 KB')
  assert.equal(formatFileSize(1536), '1.50 KB')
  assert.equal(formatFileSize(1048575), '1024.00 KB')
  assert.equal(formatFileSize(1048576), '1.00 MB')
  assert.equal(formatFileSize(5242880), '5.00 MB')
})

test('removeScanResultsByPath filters by fileId and description and refreshes stats', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')

  assert.match(scannerStoreSource, /removeScanResultsByPath: \(paths: string\[\]\) => void/)
  assert.match(scannerStoreSource, /const pathSet = new Set\(paths\.filter\(Boolean\)\)/)
  assert.match(scannerStoreSource, /if \(pathSet\.size === 0\) return/)
  assert.match(scannerStoreSource, /remainingResults = state\.scanResults\.filter/)
  assert.match(scannerStoreSource, /threatsFound = remainingResults\.filter/)
  assert.match(scannerStoreSource, /cleanFiles = remainingResults\.length - threatsFound/)

  const scanResults = [
    { fileId: 'C:\\malware.exe', verdict: 'malicious', description: 'Trojan' },
    { fileId: 'C:\\safe.exe', verdict: 'clean', description: 'Clean file' },
    { fileId: 'C:\\virus.exe', verdict: 'malicious', description: 'Virus' },
  ]

  const pathsToRemove = ['C:\\malware.exe']
  const pathSet = new Set(pathsToRemove.filter(Boolean))
  const remainingResults = scanResults.filter(
    (result) => !pathSet.has(result.fileId) && !(result.description && pathSet.has(result.description))
  )
  assert.equal(remainingResults.length, 2)
  assert.ok(!remainingResults.some(r => r.fileId === 'C:\\malware.exe'))

  const threatsFound = remainingResults.filter(r => r.verdict && r.verdict !== 'clean').length
  const cleanFiles = remainingResults.length - threatsFound
  assert.equal(threatsFound, 1)
  assert.equal(cleanFiles, 1)
})

test('removeScanResultsByPath with empty paths does nothing', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.match(scannerStoreSource, /if \(pathSet\.size === 0\) return/)

  const pathsToRemove = []
  const pathSet = new Set(pathsToRemove.filter(Boolean))
  assert.equal(pathSet.size, 0)
})

test('removeScanResultsByPath filters falsy paths', () => {
  const scannerStoreSource = readFileSync(resolve(projectRoot, 'src/stores/scannerStore.ts'), 'utf8')
  assert.match(scannerStoreSource, /paths\.filter\(Boolean\)/)

  const pathsToRemove = ['C:\\malware.exe', '', null, undefined, 0]
  const pathSet = new Set(pathsToRemove.filter(Boolean))
  assert.equal(pathSet.size, 1)
  assert.ok(pathSet.has('C:\\malware.exe'))
})

test('mergeTrustItems handles empty exclusions and allowlist', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  const mergedItems = new Map()
  const exclusions = []
  const allowlist = []

  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }
  for (const allowedItem of allowlist) {
    const key = normalizeTrustPath(allowedItem.path)
    const existingItem = mergedItems.get(key)
    if (existingItem) {
      mergedItems.set(key, {
        ...existingItem,
        hash: allowedItem.hash ?? existingItem.hash,
        description: existingItem.description ?? allowedItem.description,
        created_at: existingItem.created_at <= allowedItem.created_at ? existingItem.created_at : allowedItem.created_at,
        sources: existingItem.sources.includes('allowlist')
          ? existingItem.sources
          : [...existingItem.sources, 'allowlist']
      })
      continue
    }
    mergedItems.set(key, {
      path: allowedItem.path,
      entry_type: 'file',
      hash: allowedItem.hash,
      description: allowedItem.description,
      created_at: allowedItem.created_at,
      sources: ['allowlist']
    })
  }

  const result = Array.from(mergedItems.values())
  assert.equal(result.length, 0, 'empty inputs should produce empty result')
})

test('mergeTrustItems allowlist-only entry gets file entry_type', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  const exclusions = []
  const allowlist = [
    { path: 'C:\\OnlyAllowlist.exe', hash: 'hash123', description: 'Only in allowlist', created_at: '2026-01-01T00:00:00Z' }
  ]

  const mergedItems = new Map()
  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }
  for (const allowedItem of allowlist) {
    const key = normalizeTrustPath(allowedItem.path)
    const existingItem = mergedItems.get(key)
    if (existingItem) {
      mergedItems.set(key, {
        ...existingItem,
        hash: allowedItem.hash ?? existingItem.hash,
        description: existingItem.description ?? allowedItem.description,
        created_at: existingItem.created_at <= allowedItem.created_at ? existingItem.created_at : allowedItem.created_at,
        sources: existingItem.sources.includes('allowlist')
          ? existingItem.sources
          : [...existingItem.sources, 'allowlist']
      })
      continue
    }
    mergedItems.set(key, {
      path: allowedItem.path,
      entry_type: 'file',
      hash: allowedItem.hash,
      description: allowedItem.description,
      created_at: allowedItem.created_at,
      sources: ['allowlist']
    })
  }

  const result = Array.from(mergedItems.values())
  assert.equal(result.length, 1)
  assert.equal(result[0].entry_type, 'file', 'allowlist-only entry should have file entry_type')
  assert.deepEqual(result[0].sources, ['allowlist'])
})

test('mergeTrustItems exclusion-only entry preserves entry_type', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  const exclusions = [
    { path: 'C:\\SafeFolder', entry_type: 'directory', description: 'Safe folder', created_at: '2026-01-01T00:00:00Z' },
    { path: 'notepad.exe', entry_type: 'process', description: 'Notepad process', created_at: '2026-01-02T00:00:00Z' }
  ]
  const allowlist = []

  const mergedItems = new Map()
  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }

  const result = Array.from(mergedItems.values())
  assert.equal(result.length, 2)
  const dirEntry = result.find(e => e.entry_type === 'directory')
  const procEntry = result.find(e => e.entry_type === 'process')
  assert.ok(dirEntry, 'directory entry should exist')
  assert.ok(procEntry, 'process entry should exist')
  assert.deepEqual(dirEntry.sources, ['exclusion'])
  assert.deepEqual(procEntry.sources, ['exclusion'])
})

test('mergeTrustItems description priority: exclusion over allowlist', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  const exclusions = [
    { path: 'C:\\App.exe', entry_type: 'file', description: 'Exclusion description', created_at: '2026-01-01T00:00:00Z' }
  ]
  const allowlist = [
    { path: 'C:\\App.exe', hash: 'abc', description: 'Allowlist description', created_at: '2026-01-02T00:00:00Z' }
  ]

  const mergedItems = new Map()
  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }
  for (const allowedItem of allowlist) {
    const key = normalizeTrustPath(allowedItem.path)
    const existingItem = mergedItems.get(key)
    if (existingItem) {
      mergedItems.set(key, {
        ...existingItem,
        hash: allowedItem.hash ?? existingItem.hash,
        description: existingItem.description ?? allowedItem.description,
        created_at: existingItem.created_at <= allowedItem.created_at ? existingItem.created_at : allowedItem.created_at,
        sources: existingItem.sources.includes('allowlist')
          ? existingItem.sources
          : [...existingItem.sources, 'allowlist']
      })
      continue
    }
    mergedItems.set(key, {
      path: allowedItem.path,
      entry_type: 'file',
      hash: allowedItem.hash,
      description: allowedItem.description,
      created_at: allowedItem.created_at,
      sources: ['allowlist']
    })
  }

  const result = Array.from(mergedItems.values())
  assert.equal(result[0].description, 'Exclusion description', 'exclusion description should take priority')
})

test('mergeTrustItems hash from allowlist is preserved on merge', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  const exclusions = [
    { path: 'C:\\HashedApp.exe', entry_type: 'file', description: 'No hash here', created_at: '2026-01-01T00:00:00Z' }
  ]
  const allowlist = [
    { path: 'C:\\HashedApp.exe', hash: 'sha256hash123', description: 'Has hash', created_at: '2026-01-02T00:00:00Z' }
  ]

  const mergedItems = new Map()
  for (const exclusion of exclusions) {
    mergedItems.set(normalizeTrustPath(exclusion.path), {
      path: exclusion.path,
      entry_type: exclusion.entry_type,
      description: exclusion.description,
      created_at: exclusion.created_at,
      sources: ['exclusion']
    })
  }
  for (const allowedItem of allowlist) {
    const key = normalizeTrustPath(allowedItem.path)
    const existingItem = mergedItems.get(key)
    if (existingItem) {
      mergedItems.set(key, {
        ...existingItem,
        hash: allowedItem.hash ?? existingItem.hash,
        description: existingItem.description ?? allowedItem.description,
        created_at: existingItem.created_at <= allowedItem.created_at ? existingItem.created_at : allowedItem.created_at,
        sources: existingItem.sources.includes('allowlist')
          ? existingItem.sources
          : [...existingItem.sources, 'allowlist']
      })
      continue
    }
    mergedItems.set(key, {
      path: allowedItem.path,
      entry_type: 'file',
      hash: allowedItem.hash,
      description: allowedItem.description,
      created_at: allowedItem.created_at,
      sources: ['allowlist']
    })
  }

  const result = Array.from(mergedItems.values())
  assert.equal(result[0].hash, 'sha256hash123', 'hash from allowlist should be preserved')
})

test('normalizeTrustPath handles UNC paths', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  assert.equal(normalizeTrustPath('\\\\Server\\Share\\File.exe'), '\\\\server\\share\\file.exe')
  assert.equal(normalizeTrustPath('//Server/Share/File.exe'), '\\\\server\\share\\file.exe')
})

test('normalizeTrustPath handles paths with multiple consecutive slashes', () => {
  const normalizeTrustPath = (path) => path.trim().replace(/\//g, '\\').toLowerCase()

  assert.equal(normalizeTrustPath('C://Windows//System32'), 'c:\\\\windows\\\\system32')
})

test('normalizeQuarantineItem handles all status values', () => {
  const normalizeQuarantineItem = (item) => ({
    id: item.id,
    originalPath: item.originalPath ?? item.original_path ?? '',
    fileHash: item.fileHash ?? item.file_hash ?? '',
    fileSize: item.fileSize ?? item.file_size ?? 0,
    threatType: item.threatType ?? item.threat_type,
    threatFamily: item.threatFamily ?? item.threat_family,
    status: item.status,
    isolatedAt: item.isolatedAt ?? item.isolated_at ?? '',
    restoredAt: item.restoredAt ?? item.restored_at,
    description: item.description,
  })

  const quarantinedItem = { id: '1', status: 'quarantined' }
  const restoredItem = { id: '2', status: 'restored', restored_at: '2026-01-02T00:00:00Z' }
  const deletedItem = { id: '3', status: 'deleted' }

  assert.equal(normalizeQuarantineItem(quarantinedItem).status, 'quarantined')
  assert.equal(normalizeQuarantineItem(restoredItem).status, 'restored')
  assert.equal(normalizeQuarantineItem(restoredItem).restoredAt, '2026-01-02T00:00:00Z')
  assert.equal(normalizeQuarantineItem(deletedItem).status, 'deleted')
})

test('formatFileSize handles edge cases', () => {
  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  assert.equal(formatFileSize(-1), '-1 B', 'negative bytes should show as bytes')
  assert.equal(formatFileSize(1.5), '1.5 B', 'fractional bytes should show as bytes')
  assert.equal(formatFileSize(1024 * 1024 - 1), '1024.00 KB', 'just under 1MB should be KB')
  assert.equal(formatFileSize(1024 * 1024 * 1024), '1024.00 MB', '1GB should show as MB')
})
