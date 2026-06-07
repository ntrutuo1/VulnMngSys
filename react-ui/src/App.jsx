import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Layout, Radio, Space, Spin, Steps, Typography, message } from 'antd'
import { BugOutlined, LeftOutlined, SafetyOutlined } from '@ant-design/icons'
import { useTranslation } from 'react-i18next'
import HeaderBar from './components/HeaderBar'
import IisMsfAudit from './components/IisMsfAudit'
import IisMsfResults from './components/IisMsfResults'
import ResultTable from './components/ResultTable'
import StatusCards from './components/StatusCards'
import { fetchInventory, fetchReport, fetchStatus, startScan } from './services/apiClient'

const { Content } = Layout
const VIEW_MODE_KEY = 'vulnmngsys-view-mode'
const stages = ['strategy', 'configure', 'results']

export default function App() {
  const { t } = useTranslation()
  const [stage, setStage] = useState('strategy')
  const [scanType, setScanType] = useState('config')
  const [statusOk, setStatusOk] = useState(false)
  const [inventory, setInventory] = useState(null)
  const [report, setReport] = useState(null)
  const [msfReport, setMsfReport] = useState(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [fullScan, setFullScan] = useState(false)
  const [viewMode, setViewModeState] = useState(() => localStorage.getItem(VIEW_MODE_KEY) || 'desktop')
  const scanItems = useMemo(() => report?.items || [], [report])

  useEffect(() => {
    let active = true
    bootstrapApp(active, { setStatusOk, setInventory, setReport, t })
    return () => { active = false }
  }, [t])

  function setViewMode(nextMode) {
    const normalized = nextMode === 'mobile' ? 'mobile' : 'desktop'
    localStorage.setItem(VIEW_MODE_KEY, normalized)
    setViewModeState(normalized)
  }

  async function runConfigScan() {
    setScanLoading(true)
    try {
      const payload = await startScan({ profileKey: inventory?.profileKey, fullScan })
      if (payload?.ok) {
        setReport(payload)
        setStage('results')
        message.success(t('messages.scanDone', { passed: payload.passed, total: payload.total }))
      } else {
        message.error(payload?.error || t('messages.scanFailed'))
      }
    } catch (error) {
      message.error(t('messages.scanFailedWithError', { error: String(error) }))
    } finally {
      setScanLoading(false)
    }
  }

  return (
    <Layout className={`app-shell view-${viewMode}`}>
      <Content className="content-shell">
        <Space direction="vertical" size="large" className="stage-shell">
          <HeaderBar statusOk={statusOk} viewMode={viewMode} onViewModeChange={setViewMode} />
          <StageSteps stage={stage} />
          {inventory && !inventory.isServer ? <NonServerAlert /> : null}
          {stage === 'strategy' ? (
            <StrategyStage scanType={scanType} onChoose={setScanType} onNext={() => setStage('configure')} />
          ) : null}
          {stage === 'configure' ? (
            <ConfigureStage
              scanType={scanType}
              inventory={inventory}
              fullScan={fullScan}
              onFullScanChange={setFullScan}
              onRunConfig={runConfigScan}
              scanLoading={scanLoading}
              onBack={() => setStage('strategy')}
              onMsfReport={(payload) => {
                setMsfReport(payload)
                setStage('results')
              }}
            />
          ) : null}
          {stage === 'results' ? (
            <ResultsStage
              scanType={scanType}
              report={scanType === 'config' ? report : msfReport}
              scanItems={scanItems}
              scanLoading={scanLoading}
              inventory={inventory}
              onBack={() => setStage('configure')}
              compact={viewMode === 'mobile'}
            />
          ) : null}
        </Space>
      </Content>
    </Layout>
  )
}

async function bootstrapApp(active, setters) {
  const { setStatusOk, setInventory, setReport, t } = setters
  try {
    const status = await fetchStatus()
    if (active) setStatusOk(Boolean(status?.ok))
  } catch {
    if (active) setStatusOk(false)
  }
  try {
    const inv = await fetchInventory()
    if (active && inv?.ok) setInventory(inv.inventory)
  } catch (error) {
    message.error(t('messages.inventoryLoadFailed', { error: String(error) }))
  }
  try {
    const existingReport = await fetchReport()
    if (active && existingReport?.ok) setReport(existingReport)
  } catch {}
}

function StageSteps({ stage }) {
  const { t } = useTranslation()
  return <Steps current={stages.indexOf(stage)} items={stages.map((key) => ({ title: t(`stage.${key}`) }))} />
}

function NonServerAlert() {
  const { t } = useTranslation()
  return <Alert type="warning" showIcon message={t('alerts.nonServerTitle')} description={t('alerts.nonServerDescription')} />
}

function StrategyStage({ scanType, onChoose, onNext }) {
  const { t } = useTranslation()
  return (
    <Card className="glass-card" title={t('stage.strategyTitle')}>
      <Radio.Group value={scanType} onChange={(e) => onChoose(e.target.value)} className="strategy-grid">
        <StrategyOption value="config" icon={<SafetyOutlined />} title={t('scanType.config')} text={t('scanType.configDesc')} />
        <StrategyOption value="iis_msf" icon={<BugOutlined />} title={t('scanType.iisMsf')} text={t('scanType.iisMsfDesc')} />
      </Radio.Group>
      <Button type="primary" className="stage-primary" onClick={onNext}>{t('stage.continue')}</Button>
    </Card>
  )
}

function StrategyOption({ value, icon, title, text }) {
  return (
    <Radio.Button value={value} className="strategy-option">
      <Space direction="vertical" size={6}>
        <Typography.Text className="strategy-icon">{icon}</Typography.Text>
        <Typography.Text strong>{title}</Typography.Text>
        <Typography.Text type="secondary">{text}</Typography.Text>
      </Space>
    </Radio.Button>
  )
}

function ConfigureStage(props) {
  const { t } = useTranslation()
  if (props.scanType === 'iis_msf') {
    return <IisMsfAudit showResults={false} onReport={props.onMsfReport} onBack={props.onBack} />
  }
  return (
    <Space direction="vertical" size="middle" className="stage-shell">
      <StatusCards inventory={props.inventory} />
      <Card title={t('scan.controlsTitle')} className="glass-card">
        <Space direction="vertical" className="stage-shell">
          <Radio.Group value={props.fullScan} onChange={(event) => props.onFullScanChange(event.target.value)}>
            <Radio.Button value={false}>{t('scan.quick')}</Radio.Button>
            <Radio.Button value={true}>{t('scan.full')}</Radio.Button>
          </Radio.Group>
          <Space>
            <Button icon={<LeftOutlined />} onClick={props.onBack}>{t('stage.back')}</Button>
            <Button type="primary" onClick={props.onRunConfig} loading={props.scanLoading}>{t('scan.start')}</Button>
          </Space>
        </Space>
      </Card>
    </Space>
  )
}

function ResultsStage({ scanType, report, scanItems, scanLoading, inventory, onBack, compact }) {
  const { t } = useTranslation()
  if (scanType === 'iis_msf') return <IisMsfResults loading={false} report={report} onBack={onBack} />
  return (
    <Card title={t('scan.resultsTitle')} className="glass-card" extra={<Button icon={<LeftOutlined />} onClick={onBack}>{t('stage.back')}</Button>}>
      {scanLoading ? <Spin /> : report ? (
        <Space direction="vertical" size="middle" className="stage-shell">
          <Alert type={report.failed > 0 ? 'warning' : 'success'} showIcon message={t('report.summary', report)} description={t('report.fileLabel', { path: report.reportFile })} />
          <Typography.Text type="secondary">
            {t('scan.profileMode', { profile: report.profileKey || inventory?.profileKey || t('report.na'), mode: report.fullScan ? t('report.modeFull') : t('report.modeQuick') })}
          </Typography.Text>
          <ResultTable items={scanItems} compact={compact} />
        </Space>
      ) : <Typography.Text type="secondary">{t('scan.noResult')}</Typography.Text>}
    </Card>
  )
}
