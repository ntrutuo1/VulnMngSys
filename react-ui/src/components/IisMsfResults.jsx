import { BugOutlined, FileTextOutlined } from '@ant-design/icons'
import { Button, Card, Col, Row, Space, Spin, Table, Tag, Typography } from 'antd'
import IisMsfResultTable from './IisMsfResultTable'
import { ScoreRing, SummaryPills } from './MsfSummary'
import { StatusTag } from './IisMsfStatus'

const { Text } = Typography

export default function IisMsfResults({ loading, report, onBack }) {
  if (loading) {
    return (
      <Card className="glass-card">
        <div className="msf-loading">
          <Spin size="large" />
          <div>Running IIS Metasploit audit. This may take a few minutes.</div>
        </div>
      </Card>
    )
  }
  if (!report) {
    return (
      <Card className="glass-card">
        <div className="msf-empty">
          <BugOutlined />
          <Text type="secondary">Wait for msfrpc to connect, then run the IIS MSF audit.</Text>
        </div>
      </Card>
    )
  }
  return (
    <Card className="glass-card iis-msf-results-card" title={<ResultsTitle report={report} />} extra={onBack ? <Button onClick={onBack}>Back</Button> : null}>
      <Row gutter={[24, 16]} align="middle" style={{ marginBottom: 20 }}>
        <Col>
          <ScoreRing score={report.score ?? 0} label={report.score_label ?? '-'} color={report.score_color ?? 'red'} />
        </Col>
        <Col flex="auto">
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <SummaryPills summary={report.summary} />
            <ReportMeta report={report} />
          </Space>
        </Col>
      </Row>
      <PatchSummary items={report.kb_patch_summary || []} />
      <IisMsfResultTable items={report.results || []} />
    </Card>
  )
}

function ResultsTitle({ report }) {
  return (
    <Space size={8} wrap>
      <FileTextOutlined style={{ color: '#0f766e' }} />
      <Text strong>IIS Critical CVE Audit Results</Text>
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
  return <Tag color={value === 'CRITICAL' ? 'red' : 'orange'}>{value || '-'}</Tag>
}

function ReportMeta({ report }) {
  return (
    <Space wrap size={4} className="msf-report-meta">
      <Text type="secondary">Target: <b>{report.target}</b></Text>
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
