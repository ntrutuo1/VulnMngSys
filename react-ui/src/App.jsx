import { useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Layout, Radio, Space, Spin, Typography, message } from 'antd'
import { useTranslation } from 'react-i18next'
import HeaderBar from './components/HeaderBar'
import ServiceSelector from './components/ServiceSelector'
import StatusCards from './components/StatusCards'
import ResultTable from './components/ResultTable'
import { fetchInventory, fetchReport, fetchStatus, startScan } from './services/apiClient'

const { Content } = Layout

export default function App() {
  const { t } = useTranslation()
  const [statusOk, setStatusOk] = useState(false)
  const [inventory, setInventory] = useState(null)
  const [report, setReport] = useState(null)
  const [scanLoading, setScanLoading] = useState(false)
  const [fullScan, setFullScan] = useState(false)
  const [selectedServiceNames, setSelectedServiceNames] = useState([])

  useEffect(() => {
    let active = true

    async function bootstrap() {
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
      } catch {
        // Ignore when no prior scan exists.
      }
    }

    bootstrap()
    return () => {
      active = false
    }
  }, [])

  const detectedServices = useMemo(() => inventory?.detectedServices || [], [inventory])
  const scanItems = useMemo(() => report?.items || [], [report])

  useEffect(() => {
    const serviceNames = detectedServices
      .map((item) => item?.Name || item?.name || item?.DisplayName || item?.displayName)
      .map((value) => String(value || '').trim())
      .filter(Boolean)

    if (serviceNames.length > 0) {
      setSelectedServiceNames(serviceNames)
    } else {
      setSelectedServiceNames([])
    }
  }, [detectedServices])

  const hasDetectedServices = detectedServices.length > 0
  const hasSelectedServices = selectedServiceNames.length > 0

  async function handleStartScan() {
    if (hasDetectedServices && !hasSelectedServices) {
      message.warning(t('messages.selectServicesFirst'))
      return
    }

    setScanLoading(true)
    try {
      const payload = await startScan({
        profileKey: inventory?.profileKey,
        fullScan,
        selectedServices: hasDetectedServices ? selectedServiceNames : [],
      })
      if (payload?.ok) {
        setReport(payload)
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
    <Layout className="app-shell">
      <Content className="content-shell">
        <Space direction="vertical" size="large" style={{ width: '100%' }}>
          <HeaderBar statusOk={statusOk} />
          <Alert
            type="success"
            showIcon
            message={t('banner.readyTitle')}
            description={t('banner.readyDescription')}
          />
          {inventory && !inventory.isServer ? (
            <Alert
              type="warning"
              showIcon
              message={t('alerts.nonServerTitle')}
              description={t('alerts.nonServerDescription')}
            />
          ) : null}
          <StatusCards inventory={inventory} />
          <ServiceSelector
            services={detectedServices}
            selectedServiceNames={selectedServiceNames}
            onChange={setSelectedServiceNames}
            loading={!inventory}
          />
          <Card title={t('scan.controlsTitle')} className="glass-card">
            <Space direction="vertical" style={{ width: '100%' }}>
              <Radio.Group value={fullScan} onChange={(event) => setFullScan(event.target.value)}>
                <Radio.Button value={false}>{t('scan.quick')}</Radio.Button>
                <Radio.Button value={true}>{t('scan.full')}</Radio.Button>
              </Radio.Group>
              <Button
                type="primary"
                onClick={handleStartScan}
                loading={scanLoading}
                disabled={hasDetectedServices && !hasSelectedServices}
              >
                {t('scan.start')}
              </Button>
            </Space>
          </Card>

          <Card title={t('scan.resultsTitle')} className="glass-card">
            {scanLoading ? (
              <Spin />
            ) : report ? (
              <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                <Alert
                  type={report.failed > 0 ? 'warning' : 'success'}
                  showIcon
                  message={t('report.summary', { status: report.status, passed: report.passed, total: report.total })}
                  description={t('report.fileLabel', { path: report.reportFile })}
                />
                <Typography.Text type="secondary">
                  {t('scan.profileMode', {
                    profile: report.profileKey || inventory?.profileKey || t('report.na'),
                    mode: report.fullScan ? t('report.modeFull') : t('report.modeQuick'),
                  })}
                </Typography.Text>
                {report.selectedServices?.length ? (
                  <Typography.Text type="secondary">
                    {t('scan.selectedServicesSummary', { count: report.selectedServices.length })}
                  </Typography.Text>
                ) : null}
                <ResultTable items={scanItems} />
              </Space>
            ) : (
              <Typography.Text type="secondary">
                {t('scan.noResult')}
              </Typography.Text>
            )}
          </Card>
        </Space>
      </Content>
    </Layout>
  )
}
