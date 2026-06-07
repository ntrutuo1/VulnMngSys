function resolveApiBase() {
  const params = new URLSearchParams(window.location.search)
  return params.get('apiBase') || 'http://127.0.0.1:5000'
}

const API_BASE = resolveApiBase()

async function getJson(path) {
  const response = await fetch(`${API_BASE}${path}`)
  return response.json()
}

async function postJson(path, body) {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return response.json()
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

export function startScan({ profileKey, fullScan = false } = {}) {
  return postJson('/api/scan', {
    profileKey,
    fullScan,
    mode: fullScan ? 'full' : 'quick',
  })
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

export function startMsfAudit({ target = '127.0.0.1', activeTest = false } = {}) {
  return postJson('/api/msf/audit', { target, activeTest })
}
