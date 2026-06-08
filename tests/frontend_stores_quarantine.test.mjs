import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')

test('quarantineStore defines QuarantineState interface', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.match(quarantineStoreSource, /interface QuarantineState/)
  assert.ok(quarantineStoreSource.includes('items: QuarantineItem[]'))
  assert.ok(quarantineStoreSource.includes('loading: boolean'))
  assert.ok(quarantineStoreSource.includes('error:'))
  assert.ok(quarantineStoreSource.includes('selectedIds:'))
  assert.ok(quarantineStoreSource.includes('searchQuery:'))
})

test('quarantineStore defines QuarantineItem type', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('QuarantineItem'))
})

test('quarantineStore defines loadItems action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('loadItems'))
  assert.ok(quarantineStoreSource.includes('listQuarantine'))
})

test('quarantineStore defines restoreItem action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('restoreItem'))
  assert.ok(quarantineStoreSource.includes('restoreFile'))
})

test('quarantineStore defines deleteItem action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('deleteItem'))
  assert.ok(quarantineStoreSource.includes('deleteQuarantine'))
})

test('quarantineStore defines batchRestore action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('batchRestore'))
})

test('quarantineStore defines batchDelete action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('batchDelete'))
})

test('quarantineStore defines toggleSelection action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('toggleSelection'))
})

test('quarantineStore defines selectAll action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('selectAll'))
})

test('quarantineStore defines clearSelection action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('clearSelection'))
})

test('quarantineStore defines setSearchQuery action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('setSearchQuery'))
})

test('quarantineStore defines refresh action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('refresh'))
})

test('quarantineStore defines clearError action', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('clearError'))
})

test('quarantineStore implements getFilteredItems helper', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('getFilteredItems'))
  assert.ok(quarantineStoreSource.includes('searchQuery'))
  assert.ok(quarantineStoreSource.includes('originalPath'))
})

test('quarantineStore filters by originalPath and threatType', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('toLowerCase()'))
  assert.ok(quarantineStoreSource.includes('includes(lower)'))
})

test('quarantineStore error handling in loadItems', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('catch'))
  assert.ok(quarantineStoreSource.includes('err.message'))
})

test('quarantineStore error tracking for batch operations', () => {
  const quarantineStoreSource = readFileSync(resolve(projectRoot, 'src/stores/quarantineStore.ts'), 'utf8')
  assert.ok(quarantineStoreSource.includes('errorCount'))
})
