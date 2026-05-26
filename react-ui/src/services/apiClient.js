function resolveApiBase() {
  const params = new URLSearchParams(window.location.search)
  return params.get('apiBase') || 'http://127.0.0.1:5000'
}

const API_BASE = resolveApiBase()

export async function fetchStatus() {
  const response = await fetch(`${API_BASE}/api/status`)
  return response.json()
}

export async function fetchInventory() {
  const response = await fetch(`${API_BASE}/api/inventory`)
  return response.json()
}

export async function fetchReport() {
  const response = await fetch(`${API_BASE}/api/report`)
  return response.json()
}

export async function startScan({ profileKey, fullScan = false, selectedServices = [] } = {}) {
  const response = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      profileKey,
      fullScan,
      mode: fullScan ? 'full' : 'quick',
      selectedServices,
    }),
  })
  return response.json()
}
