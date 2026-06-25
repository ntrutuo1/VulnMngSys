import { Alert, Button, Card, Radio, Space, Spin, Steps, Typography } from 'antd'
import { BugOutlined, LeftOutlined, SafetyOutlined } from '@ant-design/icons'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import IisMsfAudit from './IisMsfAudit'
import IisMsfResults from './IisMsfResults'
import ScanProgressView from './ScanProgressView'
import ServiceDashboard from './ServiceDashboard'
import ServiceDetail from './ServiceDetail'
import ServiceSidebar from './ServiceSidebar'
import StatusCards from './StatusCards'
import { findGroup, normalizeGroups, summarizeGroups } from './serviceGroups'

const stages = ['strategy', 'configure', 'results']

export function StageSteps({ stage }) {
  const { t } = useTranslation()
  return <Steps current={stages.indexOf(stage)} items={stages.map((key) => ({ title: t(`stage.${key}`) }))} />
}

export function NonServerAlert() {
  const { t } = useTranslation()
  return <Alert type="warning" showIcon message={t('alerts.nonServerTitle')} description={t('alerts.nonServerDescription')} />
}

export function StrategyStage({ scanType, onChoose, onNext }) {
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

export function ConfigureStage(props) {
  const { t } = useTranslation()
  if (props.scanType === 'iis_msf') {
    return <IisMsfAudit showResults={false} onReport={props.onMsfReport} onBack={props.onBack} />
  }
  if (props.scanLoading) {
    return <ScanProgressView progress={props.scanProgress} />
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

export function ResultsStage({
  scanType,
  report,
  scanItems,
  serviceTree,
  scanLoading,
  reconfigLoading,
  inventory,
  selectedRuleIds = [],
  onSelectedRuleIdsChange,
  onBack,
  onReconfig,
  compact,
}) {
  const { t } = useTranslation()
  const [selectedService, setSelectedService] = useState(null)
  const groups = useMemo(() => normalizeGroups({ report, serviceTree, scanItems }), [report, serviceTree, scanItems])
  const selectedGroup = useMemo(() => findGroup(groups, selectedService), [groups, selectedService])
  const groupSummary = useMemo(() => summarizeGroups(groups), [groups])
  if (scanType === 'iis_msf') return <IisMsfResults loading={false} report={report} onBack={onBack} />
  const actions = (
    <Space>
      <Button icon={<LeftOutlined />} onClick={onBack}>{t('stage.back')}</Button>
      <Button type="primary" danger onClick={onReconfig} loading={reconfigLoading} disabled={!report || report.failed === 0 || selectedRuleIds.length === 0}>{t('scan.reconfig')}</Button>
    </Space>
  )
  return (
    <Card title={t('scan.resultsTitle')} className="glass-card" extra={actions}>
      {scanLoading ? <Spin /> : report ? (
        <Space direction="vertical" size="middle" className="stage-shell">
          <Alert type={report.failed > 0 ? 'warning' : 'success'} showIcon message={t('report.summary', report)} description={t('report.fileLabel', { path: report.reportFile })} />
          <Typography.Text type="secondary">
            {t('scan.profileMode', { profile: report.profileKey || inventory?.profileKey || t('report.na'), mode: report.fullScan ? t('report.modeFull') : t('report.modeQuick') })}
          </Typography.Text>
          <div className="results-service-layout">
            <ServiceSidebar
              groups={groups}
              selectedService={selectedGroup?.serviceId || null}
              total={report.total || report.total_rules || groupSummary.total}
              onSelect={setSelectedService}
            />
            <main className="results-service-main">
              {selectedGroup ? (
                <ServiceDetail
                  group={selectedGroup}
                  compact={compact}
                  selectedRuleIds={selectedRuleIds}
                  onSelectedRuleIdsChange={onSelectedRuleIdsChange}
                />
              ) : (
                <ServiceDashboard groups={groups} onSelect={setSelectedService} />
              )}
            </main>
          </div>
        </Space>
      ) : <Typography.Text type="secondary">{t('scan.noResult')}</Typography.Text>}
    </Card>
  )
}
