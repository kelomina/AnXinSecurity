(function (root) {
  function defaultYield() {
    return new Promise((resolve) => requestAnimationFrame(() => resolve()))
  }

  function makeYieldFn(yieldFn) {
    if (typeof yieldFn === 'function') return yieldFn
    if (typeof requestAnimationFrame === 'function') return defaultYield
    return () => Promise.resolve()
  }

  async function renderProcessSelectAsync(opts) {
    const o = opts && typeof opts === 'object' ? opts : {}
    const sel = o.sel
    if (!sel) return
    const list = Array.isArray(o.list) ? o.list : []
    const t = typeof o.t === 'function' ? o.t : ((k) => k)
    const getBaseName = typeof o.getBaseName === 'function' ? o.getBaseName : (() => '')
    const batchSize = Number.isFinite(o.batchSize) ? Math.max(50, Math.min(2000, Math.floor(o.batchSize))) : 200
    const yieldFn = makeYieldFn(o.yieldFn)
    const shouldContinue = typeof o.shouldContinue === 'function' ? o.shouldContinue : (() => true)
    const onProgress = typeof o.onProgress === 'function' ? o.onProgress : null
    const onFirstBatch = typeof o.onFirstBatch === 'function' ? o.onFirstBatch : null
    const total = list.length >>> 0

    if (!shouldContinue()) return
    sel.innerHTML = ''
    const optAll = (sel.ownerDocument && sel.ownerDocument.createElement)
      ? sel.ownerDocument.createElement('option')
      : (typeof document !== 'undefined' && document.createElement ? document.createElement('option') : null)
    if (optAll) {
      optAll.value = ''
      optAll.textContent = t('behavior_all_processes')
      sel.appendChild(optAll)
    }

    for (let i = 0; i < list.length; i += batchSize) {
      if (!shouldContinue()) return
      const frag = (sel.ownerDocument && sel.ownerDocument.createDocumentFragment)
        ? sel.ownerDocument.createDocumentFragment()
        : (typeof document !== 'undefined' && document.createDocumentFragment ? document.createDocumentFragment() : null)
      const slice = list.slice(i, i + batchSize)
      for (const p of slice) {
        if (!shouldContinue()) return
        const pid = Number.isFinite(p && p.pid) ? p.pid : null
        if (pid == null) continue
        const image = typeof p.image === 'string' ? p.image : ''
        const name = (typeof p.name === 'string' && p.name) ? p.name : getBaseName(image)
        const opt = (sel.ownerDocument && sel.ownerDocument.createElement)
          ? sel.ownerDocument.createElement('option')
          : (typeof document !== 'undefined' && document.createElement ? document.createElement('option') : null)
        if (!opt) continue
        opt.value = String(pid)
        opt.textContent = name ? `${pid} - ${name}` : String(pid)
        if (frag && frag.appendChild) frag.appendChild(opt)
        else sel.appendChild(opt)
      }
      if (frag && frag.childNodes && frag.childNodes.length > 0) sel.appendChild(frag)
      if (onProgress) {
        const done = Math.min(total, i + slice.length)
        try { onProgress(total, done) } catch {}
      }
      if (i === 0 && onFirstBatch) {
        try { onFirstBatch() } catch {}
      }
      if (i + batchSize < list.length) {
        await yieldFn()
        if (!shouldContinue()) return
      }
    }
  }

  function asPid(v) {
    const n = typeof v === 'number' ? v : parseInt(String(v), 10)
    if (!Number.isFinite(n) || n <= 0) return null
    return n
  }

  function baseName(p) {
    const s = typeof p === 'string' ? p.trim() : ''
    if (!s) return ''
    const parts = s.split(/[\\/]+/).filter(Boolean)
    return parts.length ? parts[parts.length - 1] : s
  }

  function processLabel(p) {
    const pid = asPid(p && p.pid)
    if (pid == null) return ''
    const name = (typeof p.name === 'string' && p.name.trim()) ? p.name.trim() : ''
    const image = (typeof p.image === 'string' && p.image.trim()) ? p.image.trim() : ''
    const label = name || (image ? baseName(image) : '')
    return label ? `${pid} - ${label}` : String(pid)
  }

  function eventTargetText(ev) {
    const file = (typeof ev.file_path === 'string' && ev.file_path) ? ev.file_path : ''
    const regKey = (typeof ev.reg_key === 'string' && ev.reg_key) ? ev.reg_key : ''
    const regValue = (typeof ev.reg_value === 'string' && ev.reg_value) ? ev.reg_value : ''
    const base = file || regKey || ''
    if (!base) return ''
    return regValue ? `${base} :: ${regValue}` : base
  }

  function summarizeEvent(ev) {
    const ts = (typeof ev.ts === 'string' && ev.ts) ? ev.ts : ''
    const provider = (typeof ev.provider === 'string' && ev.provider) ? ev.provider : ''
    const op = (typeof ev.op === 'string' && ev.op) ? ev.op : ''
    const tid = Number.isFinite(ev && ev.tid) ? ev.tid : null
    const target = eventTargetText(ev)
    const tail = []
    if (tid != null) tail.push(`TID ${tid}`)
    if (target) tail.push(target)
    const hint = tail.length ? tail.join(' · ') : ''
    const left = [ts, provider, op].filter(Boolean).join(' · ')
    return { label: left || 'event', hint }
  }

  function groupBy(arr, keyFn) {
    const m = new Map()
    for (const v of Array.isArray(arr) ? arr : []) {
      const k = keyFn(v)
      const key = (k == null) ? '' : String(k)
      if (!m.has(key)) m.set(key, [])
      m.get(key).push(v)
    }
    return m
  }

  function buildPidLifecycleTree(opts) {
    const o = opts && typeof opts === 'object' ? opts : {}
    const pid = asPid(o.pid)
    const t = typeof o.t === 'function' ? o.t : ((k) => k)
    const process = (o.process && typeof o.process === 'object') ? o.process : null
    const rawEvents = Array.isArray(o.events) ? o.events : []

    const events = rawEvents.slice().sort((a, b) => {
      const ia = Number.isFinite(a && a.id) ? a.id : 0
      const ib = Number.isFinite(b && b.id) ? b.id : 0
      return ia - ib
    })

    const rootLabel = pid != null ? (process ? processLabel(Object.assign({ pid }, process)) : String(pid)) : t('unknown')
    const rootNode = { kind: 'pid', pid: pid != null ? pid : null, label: rootLabel, hint: '', count: events.length, children: [] }
    if (pid == null) return rootNode

    const processEvents = events.filter((ev) => (ev && ev.provider === 'Process' && (asPid(ev.actor_pid) === pid || asPid(ev.subject_pid) === pid)))
    const fileEvents = events.filter((ev) => (ev && ev.provider === 'File' && asPid(ev.actor_pid) === pid))
    const registryEvents = events.filter((ev) => (ev && ev.provider === 'Registry' && asPid(ev.actor_pid) === pid))
    const otherEvents = events.filter((ev) => (ev && ev.provider !== 'Process' && ev.provider !== 'File' && ev.provider !== 'Registry' && (asPid(ev.actor_pid) === pid || asPid(ev.subject_pid) === pid)))

    const makeCategory = (label, evs, childrenBuilder) => {
      const node = { kind: 'category', label, hint: '', count: evs.length, children: [] }
      if (evs.length === 0) return node
      if (typeof childrenBuilder === 'function') {
        node.children = childrenBuilder(evs)
      }
      return node
    }

    const buildOpGroups = (evs) => {
      const groups = groupBy(evs, (ev) => (typeof ev.op === 'string' && ev.op) ? ev.op : t('unknown'))
      const out = []
      for (const [op, list] of groups.entries()) {
        const node = { kind: 'op', label: op, hint: '', count: list.length, children: [] }
        node.children = list.map((ev) => {
          const s = summarizeEvent(ev)
          return { kind: 'event', label: s.label, hint: s.hint, count: 1, children: [], raw: ev }
        })
        out.push(node)
      }
      out.sort((a, b) => (b.count || 0) - (a.count || 0))
      return out
    }

    const selfProc = processEvents.filter((ev) => asPid(ev.subject_pid) === pid)
    const childProc = processEvents.filter((ev) => asPid(ev.actor_pid) === pid && asPid(ev.subject_pid) != null && asPid(ev.subject_pid) !== pid)
    const relatedProc = processEvents.filter((ev) => !(asPid(ev.subject_pid) === pid) && !(asPid(ev.actor_pid) === pid && asPid(ev.subject_pid) != null && asPid(ev.subject_pid) !== pid))

    const procNode = makeCategory(t('behavior_lifecycle_category_process'), processEvents, () => {
      const children = []
      const selfNode = { kind: 'subcategory', label: t('behavior_lifecycle_subcategory_self'), hint: '', count: selfProc.length, children: buildOpGroups(selfProc) }
      const childrenNode = { kind: 'subcategory', label: t('behavior_lifecycle_subcategory_children'), hint: '', count: childProc.length, children: [] }
      if (childProc.length) {
        const bySubject = groupBy(childProc, (ev) => asPid(ev.subject_pid))
        for (const [spidStr, list] of bySubject.entries()) {
          const spid = asPid(spidStr)
          const label = spid != null ? String(spid) : t('unknown')
          const node = { kind: 'pid', pid: spid, label, hint: '', count: list.length, children: buildOpGroups(list) }
          childrenNode.children.push(node)
        }
        childrenNode.children.sort((a, b) => (b.count || 0) - (a.count || 0))
      }

      const relatedNode = { kind: 'subcategory', label: t('behavior_lifecycle_subcategory_related'), hint: '', count: relatedProc.length, children: buildOpGroups(relatedProc) }
      if (selfProc.length) children.push(selfNode)
      if (childProc.length) children.push(childrenNode)
      if (relatedProc.length) children.push(relatedNode)
      if (!children.length) children.push({ kind: 'event', label: t('behavior_lifecycle_empty'), hint: '', count: 0, children: [] })
      return children
    })

    const fileNode = makeCategory(t('behavior_lifecycle_category_file'), fileEvents, buildOpGroups)
    const regNode = makeCategory(t('behavior_lifecycle_category_registry'), registryEvents, buildOpGroups)
    const otherNode = makeCategory(t('behavior_lifecycle_category_other'), otherEvents, buildOpGroups)

    rootNode.children = [procNode, fileNode, regNode, otherNode].filter((n) => (n && typeof n === 'object'))
    return rootNode
  }

  function normalizeText(v) {
    return (typeof v === 'string') ? v.trim() : ''
  }

  function matchRule(rule, ev) {
    if (!rule || typeof rule !== 'object' || !ev || typeof ev !== 'object') return false
    const rp = normalizeText(rule.provider)
    const ro = normalizeText(rule.op)
    const rtp = normalizeText(rule.targetProvider)
    const evProvider = normalizeText(ev.provider)
    const evOp = normalizeText(ev.op)
    if (rp && rp !== evProvider) return false
    if (ro && ro !== evOp) return false

    if (rtp) {
      const file = normalizeText(ev.file_path)
      const reg = normalizeText(ev.reg_key)
      const targetProvider = file ? 'File' : (reg ? 'Registry' : '')
      if (targetProvider !== rtp) return false
    }

    const textContains = Array.isArray(rule.textContains) ? rule.textContains.map(normalizeText).filter(Boolean) : []
    if (textContains.length) {
      const target = eventTargetText(ev)
      const all = `${normalizeText(target)} ${normalizeText(ev.raw_json)}`
      for (const needle of textContains) {
        if (!needle) continue
        if (!all.includes(needle)) return false
      }
    }
    return true
  }

  function mapEventToMitre(ev, cfg) {
    const c = (cfg && typeof cfg === 'object') ? cfg : {}
    const enabled = c.enabled !== false
    if (!enabled) return []
    const rules = Array.isArray(c.rules) ? c.rules : []
    const matches = []
    for (const r of rules) {
      if (!matchRule(r, ev)) continue
      const tactic = normalizeText(r.tactic)
      const techniqueId = normalizeText(r.techniqueId)
      const techniqueName = normalizeText(r.techniqueName)
      if (!tactic || !techniqueId || !techniqueName) continue
      matches.push({ tactic, techniqueId, techniqueName })
    }
    return matches
  }

  function buildMitreMatrixModel(opts) {
    const o = opts && typeof opts === 'object' ? opts : {}
    const pid = asPid(o.pid)
    const t = typeof o.t === 'function' ? o.t : ((k) => k)
    const cfg = (o.cfg && typeof o.cfg === 'object') ? o.cfg : {}
    const rawEvents = Array.isArray(o.events) ? o.events : []
    const tactics = Array.isArray(cfg.tactics) && cfg.tactics.length ? cfg.tactics.slice() : []

    if (pid == null) {
      return { pid: null, tactics, columns: [] }
    }

    const events = rawEvents.filter((ev) => {
      const a = asPid(ev && ev.actor_pid)
      const s = asPid(ev && ev.subject_pid)
      return a === pid || s === pid
    })

    const byTactic = new Map()
    for (const tac of tactics) byTactic.set(String(tac), new Map())

    for (const ev of events) {
      const tags = mapEventToMitre(ev, cfg)
      for (const tag of tags) {
        const tactic = tag.tactic
        if (!byTactic.has(tactic)) byTactic.set(tactic, new Map())
        const techKey = `${tag.techniqueId} ${tag.techniqueName}`
        const techMap = byTactic.get(tactic)
        if (!techMap.has(techKey)) {
          techMap.set(techKey, { tactic, techniqueId: tag.techniqueId, techniqueName: tag.techniqueName, count: 0, examples: [] })
        }
        const cell = techMap.get(techKey)
        cell.count += 1
        if (cell.examples.length < 5) {
          const s = summarizeEvent(ev)
          cell.examples.push({ label: s.label, hint: s.hint })
        }
      }
    }

    const columns = tactics.map((tactic) => {
      const techMap = byTactic.get(String(tactic)) || new Map()
      const techniques = Array.from(techMap.values()).sort((a, b) => (b.count || 0) - (a.count || 0))
      return { tactic: String(tactic), techniques }
    })

    const uncovered = Array.from(byTactic.entries())
      .filter(([k]) => !tactics.includes(k))
      .map(([k]) => k)
      .sort((a, b) => a.localeCompare(b))

    for (const tactic of uncovered) {
      const techMap = byTactic.get(tactic) || new Map()
      const techniques = Array.from(techMap.values()).sort((a, b) => (b.count || 0) - (a.count || 0))
      columns.push({ tactic, techniques })
    }

    const matchedCount = columns.reduce((sum, c2) => sum + (Array.isArray(c2.techniques) ? c2.techniques.reduce((s2, it) => s2 + (it.count || 0), 0) : 0), 0)
    const totalEvents = events.length
    const unmatched = Math.max(0, totalEvents - matchedCount)
    return { pid, tactics: columns.map(c3 => c3.tactic), columns, totalEvents, matchedEvents: matchedCount, unmatchedEvents: unmatched, emptyText: t('behavior_mitre_empty') }
  }

  root.behaviorRender = root.behaviorRender || {}
  root.behaviorRender.renderProcessSelectAsync = renderProcessSelectAsync
  root.behaviorRender.buildPidLifecycleTree = buildPidLifecycleTree
  root.behaviorRender.buildMitreMatrixModel = buildMitreMatrixModel

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { renderProcessSelectAsync, buildPidLifecycleTree, buildMitreMatrixModel, mapEventToMitre }
  }
})(typeof window !== 'undefined' ? window : globalThis)
