import { useEffect, useState } from 'react'
import { Button, Card, Progress, Space, Spin, Typography, message } from 'antd'
import { LeftOutlined, LoadingOutlined } from '@ant-design/icons'
import { cancelMsfAudit, fetchMsfReport, fetchMsfStatus, startMsfAudit } from '../services/apiClient'
import IisMsfControls from './IisMsfControls'
import IisMsfResults from './IisMsfResults'
import MsfStatusCard from './MsfStatusCard'

export default function IisMsfAudit({ showResults = true, onReport, onBack }) {
  const [status, setStatus] = useState(null)
  const [statusLoading, setStatusLoading] = useState(false)
  const [auditLoading, setAuditLoading] = useState(false)
  const [report, setReport] = useState(null)
  const [target, setTarget] = useState('127.0.0.1')
  const [selectedServices, setSelectedServices] = useState(['iis'])

  useEffect(() => {
    refreshStatus()
    fetchMsfReport()
      .then((data) => {
        if (data?.ok && data?.results) setReport(data)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    if (!auditLoading) return undefined
    const timer = window.setInterval(() => {
      fetchMsfReport()
        .then((data) => {
          if (data?.ok && data?.results) {
            setReport(data)
          }
        })
        .catch(() => {})
    }, 2000)
    return () => window.clearInterval(timer)
  }, [auditLoading])

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
    if (!selectedServices.length) {
      message.warning('Select at least one service to scan.')
      return
    }
    setAuditLoading(true)
    try {
      const payload = await startMsfAudit({
        target,
        activeTest: true,
        services: selectedServices,
      })
      if (payload?.ok) {
        setReport(payload)
        if (onReport) onReport(payload)
        const text = payload.scanStatus === 'CANCELLED' ? 'Service scan stopped' : 'Service scan complete'
        message.success(`${text}: ${payload.score}/100 (${payload.score_label})`)
      } else {
        message.error(payload?.error || 'IIS service scan failed')
      }
    } catch (error) {
      message.error(`Audit failed: ${error}`)
    } finally {
      setAuditLoading(false)
      refreshStatus()
    }
  }

  async function handleStopAudit() {
    try {
      await cancelMsfAudit()
      const current = await fetchMsfReport().catch(() => null)
      if (current?.ok && current?.results) {
        setReport(current)
        if (onReport) onReport(current)
      }
      message.info('Stop requested. Current module will finish, then scan will stop.')
    } catch (error) {
      message.error(`Stop failed: ${error}`)
    }
  }

  function handleSelectedServicesChange(values) {
    if (values.includes('all') && !selectedServices.includes('all')) {
      setSelectedServices(['all'])
      return
    }
    const withoutAll = values.filter((value) => value !== 'all')
    setSelectedServices(withoutAll.length ? withoutAll : [])
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      {onBack ? <Button icon={<LeftOutlined />} onClick={onBack}>Back</Button> : null}
      <MsfStatusCard status={status} loading={statusLoading} onRefresh={refreshStatus} />
      <IisMsfControls
        connected={Boolean(status?.connected)}
        target={target}
        selectedServices={selectedServices}
        loading={auditLoading}
        onTargetChange={setTarget}
        onSelectedServicesChange={handleSelectedServicesChange}
        onRun={handleRunAudit}
        onStop={handleStopAudit}
      />
      {auditLoading ? (
        <Card className="glass-card" style={{ marginTop: 8 }}>
          <Space direction="vertical" size={14} style={{ width: '100%', textAlign: 'center', padding: '10px 0' }}>
            <Spin indicator={<LoadingOutlined style={{ fontSize: 24, color: '#0f766e' }} spin />} />
            <Typography.Text strong style={{ fontSize: '15px', color: '#1e293b' }}>
              Service scan in progress...
            </Typography.Text>
            {report && Number.isFinite(report.completedModules) && Number.isFinite(report.totalModules) ? (
              <div style={{ maxWidth: 400, margin: '0 auto', width: '100%' }}>
                <Progress
                  percent={Math.round((report.completedModules / report.totalModules) * 100)}
                  strokeColor="#0f766e"
                  status="active"
                />
                <Typography.Text type="secondary" style={{ fontSize: '12px', display: 'block', marginTop: 4 }}>
                  Scanned {report.completedModules} of {report.totalModules} modules
                </Typography.Text>
              </div>
            ) : (
              <Typography.Text type="secondary">Initializing Metasploit modules...</Typography.Text>
            )}
          </Space>
        </Card>
      ) : null}
      {showResults ? <IisMsfResults loading={auditLoading} report={report} /> : null}
    </Space>
  )
}
