import { useEffect, useMemo, useState } from 'react'
import { Layout, Space, message } from 'antd'
import { useTranslation } from 'react-i18next'
import { ConfigureStage, NonServerAlert, ResultsStage, StageSteps, StrategyStage } from './components/ConfigWorkflowStages'
import HeaderBar from './components/HeaderBar'
import { fetchInventory, fetchReport, fetchStatus, runReconfig, startScan } from './services/apiClient'

const { Content } = Layout
const VIEW_MODE_KEY = 'vulnmngsys-view-mode'

export default function App() {
  const { t } = useTranslation()
  const [stage, setStage] = useState('strategy')
  const [scanType, setScanType] = useState('config')
  const [statusOk, setStatusOk] = useState(false)
  const [inventory, setInventory] = useState(null)
  const [report, setReport] = useState(null)
  const [msfReport, setMsfReport] = useState(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [reconfigLoading, setReconfigLoading] = useState(false)
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

  async function runConfigReconfig() {
    setReconfigLoading(true)
    try {
      const payload = await runReconfig()
      if (payload?.ok) {
        message.success(t('messages.reconfigDone', { applied: payload.applied, skipped: payload.skipped }))
        setStage('configure')
      } else {
        message.error(payload?.stderr || payload?.error || t('messages.reconfigFailed'))
      }
    } catch (error) {
      message.error(t('messages.reconfigFailedWithError', { error: String(error) }))
    } finally {
      setReconfigLoading(false)
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
              reconfigLoading={reconfigLoading}
              inventory={inventory}
              onBack={() => setStage('configure')}
              onReconfig={runConfigReconfig}
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
