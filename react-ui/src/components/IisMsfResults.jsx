import { BugOutlined, FileTextOutlined } from '@ant-design/icons'
import { Button, Card, Col, Modal, Row, Space, Spin, Table, Tag, Typography, message } from 'antd'
import IisMsfResultTable from './IisMsfResultTable'
import { ScoreRing, SummaryPills, SeverityPieChart } from './MsfSummary'
import { StatusTag } from './IisMsfStatus'
import { runMsfReconfig } from '../services/apiClient'

const { Text } = Typography

export default function IisMsfResults({ loading, report, onBack }) {
  async function handleReconfig() {
    const selectedCves = failedCves(report)
    const preview = await runMsfReconfig({ selectedCves })
    if (!preview?.ok) {
      message.error(preview?.error || 'IIS service remediation preview failed')
      return
    }
    Modal.confirm({
      title: 'Review IIS service remediation',
      content: `Selected ${preview.selected} finding(s). Backup will be created before apply; rollback runs if IIS services stop.`,
      okText: 'Apply',
      cancelText: 'Cancel',
      onOk: async () => {
        const payload = await runMsfReconfig({ apply: true, selectedCves })
        if (payload?.ok) {
          message.success('IIS service remediation plan applied. Re-run the service scan after installing patches.')
        } else {
          message.error(payload?.stderr || payload?.error || 'IIS service remediation failed')
        }
      },
    })
  }

  if (loading && !report) {
    return (
      <Card className="glass-card">
        <div className="msf-loading">
          <Spin size="large" />
          <div>Running service scan. Results will appear as modules finish.</div>
        </div>
      </Card>
    )
  }
  if (!report) {
    return (
      <Card className="glass-card">
        <div className="msf-empty">
          <BugOutlined />
          <Text type="secondary">Choose IIS service and run the service scan.</Text>
        </div>
      </Card>
    )
  }
  return (
    <Card
      className="glass-card iis-msf-results-card"
      title={<ResultsTitle report={report} />}
      extra={<ResultActions report={report} onBack={onBack} onReconfig={handleReconfig} />}
    >
      <Row gutter={[24, 16]} align="middle" style={{ marginBottom: 20 }}>
        <Col>
          <ScoreRing score={report.score ?? 0} label={report.score_label ?? '-'} color={report.score_color ?? 'red'} />
        </Col>
        <Col>
          <SeverityPieChart summary={report.summary} />
        </Col>
        <Col flex="auto">
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <SummaryPills summary={report.summary} />
            {loading ? <Text type="secondary">Running... showing results collected so far.</Text> : null}
            <ReportMeta report={report} />
          </Space>
        </Col>
      </Row>
      <PatchSummary items={report.kb_patch_summary || []} />
      <IisMsfResultTable items={report.results || []} />
    </Card>
  )
}

function ResultActions({ report, onBack, onReconfig }) {
  const hasFindings = failedCves(report).length > 0
  return (
    <Space>
      {onBack ? <Button onClick={onBack}>Back</Button> : null}
      <Button type="primary" danger disabled={!hasFindings} onClick={onReconfig}>Reconfig IIS Service</Button>
    </Space>
  )
}

function failedCves(report) {
  const rows = report?.results || []
  const statuses = new Set(['FAIL', 'WARNING', 'ERROR'])
  return [...new Set(
    rows
      .filter((row) => statuses.has(String(row.status || '').toUpperCase()))
      .flatMap((row) => row.cve || []),
  )]
}

function ResultsTitle({ report }) {
  return (
    <Space size={8} wrap>
      <FileTextOutlined style={{ color: '#0f766e' }} />
      <Text strong>IIS Service Scan Results</Text>
      <Tag color={report.scan_mode === 'active' ? 'orange' : 'cyan'}>{report.scan_mode?.toUpperCase()} MODE</Tag>
    </Space>
  )
}

function PatchSummary({ items }) {
  if (!items.length) return null
  return (
    <div className="iis-msf-patch-summary">
      <Text strong>KB Patch Summary</Text>
      <Table
        rowKey={(row) => row.cve}
        size="small"
        pagination={false}
        dataSource={items}
        columns={[
          {
            title: 'CVE',
            dataIndex: 'cve',
            key: 'cve',
            width: 150,
            render: (value) => <Typography.Text code>{value}</Typography.Text>,
          },
          {
            title: 'Severity',
            dataIndex: 'severity',
            key: 'severity',
            width: 100,
            render: (value) => <SeverityTag severity={value} />,
          },
          {
            title: 'Local Check',
            dataIndex: 'status',
            key: 'status',
            width: 120,
            render: (value) => <StatusTag status={value} />,
          },
          {
            title: 'Patch Baseline',
            dataIndex: 'patch_after',
            key: 'patch_after',
            width: 130,
          },
          {
            title: 'Installed HotFixes',
            dataIndex: 'installed_hotfixes',
            key: 'installed_hotfixes',
            render: (value) => (value?.length ? value.join(', ') : <Text type="secondary">-</Text>),
          },
          {
            title: 'Required Patch',
            dataIndex: 'required_patch',
            key: 'required_patch',
            ellipsis: true,
            render: (value) => <Text ellipsis={{ tooltip: value }}>{value || '-'}</Text>,
          },
        ]}
        scroll={{ x: 860 }}
      />
    </div>
  )
}

function SeverityTag({ severity }) {
  const value = String(severity || '').toUpperCase()
  const colorMap = {
    HIGH: 'red',
    MEDIUM: 'orange',
    LOW: 'gold',
    INFO: 'blue',
  }
  const tagColor = colorMap[value] || 'default'
  return <Tag color={tagColor}>{value || '-'}</Tag>
}

function ReportMeta({ report }) {
  return (
    <Space wrap size={4} className="msf-report-meta">
      <Text type="secondary">Target: <b>{report.target}</b></Text>
      {report.scanStatus ? (
        <>
          <Text type="secondary">·</Text>
          <Tag color={report.scanStatus === 'CANCELLED' ? 'orange' : report.scanStatus === 'RUNNING' ? 'blue' : 'green'}>{report.scanStatus}</Tag>
        </>
      ) : null}
      {Number.isFinite(report.completedModules) && Number.isFinite(report.totalModules) ? (
        <>
          <Text type="secondary">·</Text>
          <Text type="secondary">{report.completedModules}/{report.totalModules} modules</Text>
        </>
      ) : null}
      <Text type="secondary">·</Text>
      <Text type="secondary">{report.timestamp?.split('T')[0]}</Text>
      {report.reportFile ? (
        <>
          <Text type="secondary">·</Text>
          <Text type="secondary">JSON: {report.reportFile}</Text>
        </>
      ) : null}
    </Space>
  )
}
