import { useEffect, useState } from 'react'
import { Button, Space, message } from 'antd'
import { LeftOutlined } from '@ant-design/icons'
import { fetchMsfReport, fetchMsfStatus, startMsfAudit } from '../services/apiClient'
import IisMsfControls from './IisMsfControls'
import IisMsfResults from './IisMsfResults'
import MsfStatusCard from './MsfStatusCard'

const DEFAULT_PORTS = [80, 443, 8172, 8530, 8531]
const DEFAULT_CVES = ['CVE-2025-53772', 'CVE-2025-27473', 'CVE-2025-59282', 'CVE-2025-59287']
const LOCAL_ONLY_CVES = new Set(['CVE-2025-59282'])

export default function IisMsfAudit({ showResults = true, onReport, onBack }) {
  const [status, setStatus] = useState(null)
  const [statusLoading, setStatusLoading] = useState(false)
  const [auditLoading, setAuditLoading] = useState(false)
  const [report, setReport] = useState(null)
  const [target, setTarget] = useState('127.0.0.1')
  const [selectedPorts, setSelectedPorts] = useState(DEFAULT_PORTS)
  const [selectedCves, setSelectedCves] = useState(DEFAULT_CVES)

  useEffect(() => {
    refreshStatus()
    fetchMsfReport()
      .then((data) => {
        if (data?.ok && data?.results) setReport(data)
      })
      .catch(() => {})
  }, [])

  async function refreshStatus() {
    setStatusLoading(true)
    try {
      setStatus(await fetchMsfStatus())
    } catch (error) {
      setStatus({ ok: false, connected: false, message: String(error) })
    } finally {
      setStatusLoading(false)
    }
  }

  async function handleRunAudit() {
    if (!selectedCves.length) {
      message.warning('Select at least one CVE to scan.')
      return
    }
    const needsPort = selectedCves.some((cve) => !LOCAL_ONLY_CVES.has(cve))
    if (needsPort && !selectedPorts.length) {
      message.warning('Select at least one port for CVEs that require an MSF probe.')
      return
    }
    setAuditLoading(true)
    try {
      const payload = await startMsfAudit({
        target,
        activeTest: false,
        ports: selectedPorts,
        selectedCves,
      })
      if (payload?.ok) {
        setReport(payload)
        if (onReport) onReport(payload)
        message.success(`IIS Audit complete: ${payload.score}/100 (${payload.score_label})`)
      } else {
        message.error(payload?.error || 'IIS Audit failed')
      }
    } catch (error) {
      message.error(`Audit failed: ${error}`)
    } finally {
      setAuditLoading(false)
      refreshStatus()
    }
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      {onBack ? <Button icon={<LeftOutlined />} onClick={onBack}>Back</Button> : null}
      <MsfStatusCard status={status} loading={statusLoading} onRefresh={refreshStatus} />
      <IisMsfControls
        connected={Boolean(status?.connected)}
        target={target}
        selectedPorts={selectedPorts}
        selectedCves={selectedCves}
        loading={auditLoading}
        onTargetChange={setTarget}
        onSelectedPortsChange={setSelectedPorts}
        onSelectedCvesChange={setSelectedCves}
        onRun={handleRunAudit}
      />
      {showResults ? <IisMsfResults loading={auditLoading} report={report} /> : null}
    </Space>
  )
}
