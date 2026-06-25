export function normalizeGroups({ report, serviceTree, scanItems = [] } = {}) {
  const reportGroups = Array.isArray(report?.groups) ? report.groups : []
  if (reportGroups.length > 0) return reportGroups
  const treeGroups = Array.isArray(serviceTree?.groups) ? serviceTree.groups : []
  if (treeGroups.length > 0 && (!scanItems || scanItems.length === 0)) return treeGroups
  return fallbackGroupsFromItems(scanItems)
}

export function fallbackGroupsFromItems(items = []) {
  const map = new Map()
  for (const item of items || []) {
    const serviceId = item.serviceName || item.service_name || item.service || 'Uncategorized'
    if (!map.has(serviceId)) {
      map.set(serviceId, {
        serviceId,
        label: labelFromId(serviceId),
        category: 'dynamic',
        total: 0,
        passed: 0,
        failed: 0,
        manual: 0,
        items: [],
      })
    }
    const group = map.get(serviceId)
    group.items.push(item)
  }
  return Array.from(map.values()).map(finalizeGroup)
}

export function flattenGroupItems(group) {
  if (!group) return []
  const own = Array.isArray(group.items) ? group.items : []
  const childItems = (group.subgroups || []).flatMap((child) => flattenGroupItems(child))
  return [...own, ...childItems]
}

export function flattenGroups(groups = []) {
  return (groups || []).flatMap((group) => [group, ...(group.subgroups || [])])
}

export function findGroup(groups = [], serviceId) {
  if (!serviceId) return null
  const key = normalizeKey(serviceId)
  return flattenGroups(groups).find((group) => normalizeKey(group.serviceId) === key) || null
}

export function groupStatus(group) {
  if ((group?.failed || 0) > 0) return 'fail'
  if ((group?.manual || 0) > 0) return 'manual'
  return 'pass'
}

export function compliance(group) {
  const total = Number(group?.total || 0)
  if (total <= 0) return 0
  return Math.round((Number(group?.passed || 0) / total) * 100)
}

export function summarizeGroups(groups = []) {
  const summary = { total: 0, passed: 0, failed: 0, manual: 0 }
  for (const group of groups || []) {
    summary.total += Number(group.total || 0)
    summary.passed += Number(group.passed || 0)
    summary.failed += Number(group.failed || 0)
    summary.manual += Number(group.manual || 0)
  }
  summary.compliance = summary.total > 0 ? Math.round((summary.passed / summary.total) * 100) : 0
  return summary
}

function finalizeGroup(group) {
  const counts = countItems(group.items || [])
  return { ...group, ...counts, compliance: compliance(counts) }
}

function countItems(items = []) {
  const counts = { total: items.length, passed: 0, failed: 0, manual: 0 }
  for (const item of items) {
    const verdict = String(item.verdict || (item.passed ? 'PASS' : 'FAIL')).toUpperCase()
    if (verdict === 'PASS') counts.passed += 1
    else if (verdict === 'MANUAL') counts.manual += 1
    else counts.failed += 1
  }
  return counts
}

function labelFromId(value) {
  return String(value || 'Uncategorized').replace(/[_-]/g, ' ')
}

function normalizeKey(value) {
  return String(value || '').replace(/\s+/g, '_').toLowerCase()
}
