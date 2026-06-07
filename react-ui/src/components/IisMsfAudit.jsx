import { useEffect, useState } from 'react'
import { Button, Space, message } from 'antd'
import { LeftOutlined } from '@ant-design/icons'
import { fetchMsfReport, fetchMsfStatus, startMsfAudit } from '../services/apiClient'
import IisMsfControls from './IisMsfControls'
import IisMsfResults from './IisMsfResults'
import MsfStatusCard from './MsfStatusCard'

export default function IisMsfAudit({ showResults = true, onReport, onBack }) {
  const [status, setStatus] = useState(null)
  const [statusLoading, setStatusLoading] = useState(false)
  const [auditLoading, setAuditLoading] = useState(false)
  const [report, setReport] = useState(null)
  const [target, setTarget] = useState('127.0.0.1')
  const [activeTest, setActiveTest] = useState(false)

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
    setAuditLoading(true)
    try {
      const payload = await startMsfAudit({ target, activeTest })
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
        activeTest={activeTest}
        loading={auditLoading}
        onTargetChange={setTarget}
        onActiveTestChange={setActiveTest}
        onRun={handleRunAudit}
      />
      {showResults ? <IisMsfResults loading={auditLoading} report={report} /> : null}
    </Space>
  )
}
