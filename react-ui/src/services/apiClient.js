function resolveApiBase() {
  const params = new URLSearchParams(window.location.search)
  return params.get('apiBase') || 'http://127.0.0.1:5000'
}

function resolveApiToken() {
  const params = new URLSearchParams(window.location.search)
  return params.get('apiToken') || ''
}

const API_BASE = resolveApiBase()
const API_TOKEN = resolveApiToken()

function authHeaders(extra = {}) {
  return API_TOKEN ? { ...extra, 'X-VulnMngSys-Token': API_TOKEN } : extra
}

async function getJson(path) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: authHeaders(),
  })
  return parseJsonResponse(response)
}

async function postJson(path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  })
  return parseJsonResponse(response)
}

async function parseJsonResponse(response) {
  const text = await response.text()
  let payload = {}
  try {
    payload = text ? JSON.parse(text) : {}
  } catch {
    payload = { ok: false, error: text || response.statusText || 'Invalid server response' }
  }
  if (!response.ok && payload && payload.ok !== false) {
    payload.ok = false
    payload.error = payload.error || response.statusText || `HTTP ${response.status}`
  }
  return payload
}

export function fetchStatus() {
  return getJson('/api/status')
}

export function fetchInventory() {
  return getJson('/api/inventory')
}

export function fetchReport() {
  return getJson('/api/report')
}

export function fetchServiceTree() {
  return getJson('/api/service-tree')
}

export function fetchScanProgress(scanId) {
  return getJson(`/api/scan/progress?scanId=${encodeURIComponent(scanId || '')}`)
}

export function startScan({ profileKey, fullScan = false, scanId = '' } = {}) {
  return postJson('/api/scan', {
    scanId,
    profileKey,
    fullScan,
    mode: fullScan ? 'full' : 'quick',
  })
}

export function runReconfig({ apply = false, selectedRuleIds = [] } = {}) {
  return postJson('/api/reconfig', { apply, selectedRuleIds })
}

export function fetchMsfModules(activeTest = false) {
  return getJson(`/api/msf/modules${activeTest ? '?active_test=true' : ''}`)
}

export function fetchMsfStatus() {
  return getJson('/api/msf/status')
}

export function fetchMsfReport() {
  return getJson('/api/msf/report')
}

export function startMsfAudit({ target = '127.0.0.1', activeTest = false, ports, selectedCves } = {}) {
  return postJson('/api/msf/audit', { target, activeTest, ports, selectedCves })
}
