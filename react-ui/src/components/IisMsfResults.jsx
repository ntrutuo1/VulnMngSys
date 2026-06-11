import { BugOutlined, FileTextOutlined } from '@ant-design/icons'
import { Button, Card, Col, Row, Space, Spin, Tag, Typography } from 'antd'
import IisMsfResultTable from './IisMsfResultTable'
import { ScoreRing, SummaryPills } from './MsfSummary'

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
      <IisMsfResultTable items={report.results || []} />
    </Card>
  )
}

function ResultsTitle({ report }) {
  return (
    <Space size={8} wrap>
      <FileTextOutlined style={{ color: '#0f766e' }} />
      <Text strong>Audit Results</Text>
      <Tag color={report.scan_mode === 'active' ? 'orange' : 'cyan'}>{report.scan_mode?.toUpperCase()} MODE</Tag>
    </Space>
  )
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
