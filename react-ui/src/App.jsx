import { useEffect, useMemo, useState } from 'react'
import { Layout, Modal, Space, message } from 'antd'
import { useTranslation } from 'react-i18next'
import { ConfigureStage, NonServerAlert, ResultsStage, StageSteps, StrategyStage } from './components/ConfigWorkflowStages'
import HeaderBar from './components/HeaderBar'
import { fetchInventory, fetchReport, fetchScanProgress, fetchServiceTree, fetchStatus, runReconfig, startScan } from './services/apiClient'

const { Content } = Layout
const VIEW_MODE_KEY = 'vulnmngsys-view-mode'

export default function App() {
  const { t } = useTranslation()
  const [stage, setStage] = useState('strategy')
  const [scanType, setScanType] = useState('config')
  const [statusOk, setStatusOk] = useState(false)
  const [inventory, setInventory] = useState(null)
  const [report, setReport] = useState(null)
  const [serviceTree, setServiceTree] = useState(null)
  const [msfReport, setMsfReport] = useState(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [activeScanId, setActiveScanId] = useState('')
  const [scanProgress, setScanProgress] = useState(null)
  const [reconfigLoading, setReconfigLoading] = useState(false)
  const [fullScan, setFullScan] = useState(false)
  const [selectedRuleIds, setSelectedRuleIds] = useState([])
  const [viewMode, setViewModeState] = useState(() => localStorage.getItem(VIEW_MODE_KEY) || 'desktop')
  const scanItems = useMemo(() => report?.items || [], [report])

  useEffect(() => {
    setSelectedRuleIds(failedRuleIds(scanItems))
  }, [scanItems])

  useEffect(() => {
    let active = true
    bootstrapApp(active, { setStatusOk, setInventory, setReport, setServiceTree, t })
    return () => { active = false }
  }, [t])

  useEffect(() => {
    if (!scanLoading || !activeScanId) return undefined
    let active = true
    async function refreshProgress() {
      try {
        const payload = await fetchScanProgress(activeScanId)
        if (active && payload?.ok) setScanProgress(payload)
      } catch {}
    }
    refreshProgress()
    const timer = window.setInterval(refreshProgress, 700)
    return () => {
      active = false
      window.clearInterval(timer)
    }
  }, [scanLoading, activeScanId])

  function setViewMode(nextMode) {
    const normalized = nextMode === 'mobile' ? 'mobile' : 'desktop'
    localStorage.setItem(VIEW_MODE_KEY, normalized)
    setViewModeState(normalized)
  }

  async function runConfigScan() {
    const scanId = createScanId()
    setActiveScanId(scanId)
    setScanProgress({
      ok: true,
      scanId,
      status: 'running',
      total: 0,
      completed: 0,
      percent: 0,
      currentRule: null,
      recentRules: [],
    })
    setScanLoading(true)
    try {
      const payload = await startScan({ profileKey: inventory?.profileKey, fullScan, scanId })
      if (payload?.ok) {
        setReport(payload)
        setSelectedRuleIds(failedRuleIds(payload.items || []))
        setStage('results')
        message.success(t('messages.scanDone', { passed: payload.passed, total: payload.total }))
      } else {
        message.error(payload?.error || t('messages.scanFailed'))
      }
    } catch (error) {
      message.error(t('messages.scanFailedWithError', { error: String(error) }))
    } finally {
      setScanLoading(false)
      setActiveScanId('')
    }
  }

  async function runConfigReconfig() {
    setReconfigLoading(true)
    try {
      const preview = await runReconfig({ selectedRuleIds })
      if (preview?.ok) {
        Modal.confirm({
          title: t('messages.reconfigReviewTitle'),
          content: t('messages.reconfigReviewBody', { applied: preview.applied, skipped: preview.skipped, selected: preview.selected, backupDir: preview.backupDir }),
          okText: t('messages.reconfigApply'),
          cancelText: t('messages.reconfigCancel'),
          onOk: async () => {
            const payload = await runReconfig({ apply: true, selectedRuleIds })
            if (payload?.ok) {
              message.success(t('messages.reconfigDone', { applied: payload.applied, skipped: payload.skipped }))
              if (Array.isArray(payload.serviceWarnings) && payload.serviceWarnings.length > 0) {
                message.warning(t('messages.serviceWarning', { count: payload.serviceWarnings.length }))
              }
              setStage('configure')
            } else {
              message.error(payload?.stderr || payload?.error || t('messages.reconfigFailed'))
            }
          },
        })
      } else {
        message.error(preview?.stderr || preview?.error || t('messages.reconfigFailed'))
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
              scanProgress={scanProgress}
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
              serviceTree={serviceTree}
              selectedRuleIds={selectedRuleIds}
              onSelectedRuleIdsChange={setSelectedRuleIds}
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

function createScanId() {
  return `scan-${Date.now()}-${Math.random().toString(16).slice(2)}`
}

function failedRuleIds(items = []) {
  return items
    .filter((item) => String(item.verdict || (item.passed ? 'PASS' : 'FAIL')).toUpperCase() === 'FAIL')
    .map((item) => item.ruleId || item.rule_id || item.id || item.title)
    .filter(Boolean)
}

async function bootstrapApp(active, setters) {
  const { setStatusOk, setInventory, setReport, setServiceTree, t } = setters
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
  try {
    const tree = await fetchServiceTree()
    if (active && tree?.ok) setServiceTree(tree)
  } catch {}
}
