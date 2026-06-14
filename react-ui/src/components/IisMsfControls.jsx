import { Alert, Button, Checkbox, Col, Divider, Input, Row, Space, Tag, Typography } from 'antd'
import { BugOutlined, CloseCircleFilled, PlayCircleOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons'

const { Text } = Typography

const PORT_OPTIONS = [
  { value: 80, label: 'HTTP', detail: '80', cve: 'CVE-2025-27473' },
  { value: 443, label: 'HTTPS', detail: '443', cve: 'CVE-2025-27473' },
  { value: 8172, label: 'Web Deploy', detail: '8172', cve: 'CVE-2025-53772' },
  { value: 8530, label: 'WSUS HTTP', detail: '8530', cve: 'CVE-2025-59287' },
  { value: 8531, label: 'WSUS HTTPS', detail: '8531', cve: 'CVE-2025-59287' },
]

const CVE_OPTIONS = [
  { value: 'CVE-2025-53772', title: 'Web Deploy RCE', severity: 'CRITICAL', port: '8172' },
  { value: 'CVE-2025-27473', title: 'HTTP.sys DoS', severity: 'HIGH', port: '80/443' },
  { value: 'CVE-2025-59282', title: 'Inbox COM Race', severity: 'HIGH', port: 'Local' },
  { value: 'CVE-2025-59287', title: 'WSUS RCE', severity: 'CRITICAL', port: '8530/8531' },
]

const LOCAL_ONLY_CVES = new Set(['CVE-2025-59282'])

export default function IisMsfControls({
  connected,
  target,
  selectedPorts,
  selectedCves,
  loading,
  onTargetChange,
  onSelectedPortsChange,
  onSelectedCvesChange,
  onRun,
}) {
  const requiresMsf = selectedCves.some((cve) => !LOCAL_ONLY_CVES.has(cve))
  const canRun = connected || !requiresMsf

  return (
    <div className="glass-card ant-card ant-card-small iis-msf-controls-card">
      <div className="ant-card-head">
        <div className="ant-card-head-wrapper">
          <div className="ant-card-head-title"><PanelTitle /></div>
        </div>
      </div>
      <div className="ant-card-body">
        {!connected && requiresMsf ? (
          <Alert
            type="warning"
            showIcon
            icon={<CloseCircleFilled />}
            message="Metasploit RPC is not ready"
            description="MSF-backed CVE probes will be enabled after the backend starts local msfrpcd. Local-only CVE checks can run without RPC."
            style={{ marginBottom: 16 }}
          />
        ) : null}
        <Row gutter={[16, 12]} align="middle" wrap>
          <Col>
            <Space align="center">
              <Text type="secondary">Target:</Text>
              <Input value={target} onChange={(e) => onTargetChange(e.target.value)} style={{ width: 160 }} disabled={loading} />
            </Space>
          </Col>
          <Col>
            <Button
              type="primary"
              icon={loading ? <ReloadOutlined spin /> : <PlayCircleOutlined />}
              loading={loading}
              disabled={!canRun}
              onClick={onRun}
            >
              Run IIS CVE Audit
            </Button>
          </Col>
        </Row>

        <Divider style={{ margin: '14px 0' }} />
        <SectionTitle>Port Configuration</SectionTitle>
        <Checkbox.Group value={selectedPorts} onChange={onSelectedPortsChange} disabled={loading} className="iis-msf-option-grid">
          {PORT_OPTIONS.map((option) => (
            <Checkbox key={option.value} value={option.value} className="iis-msf-option">
              <Space direction="vertical" size={0}>
                <Text strong>{option.label} ({option.detail})</Text>
                <Text type="secondary">{option.cve}</Text>
              </Space>
            </Checkbox>
          ))}
        </Checkbox.Group>

        <Divider style={{ margin: '14px 0' }} />
        <SectionTitle>CVE Selection</SectionTitle>
        <Checkbox.Group value={selectedCves} onChange={onSelectedCvesChange} disabled={loading} className="iis-msf-option-grid cve-option-grid">
          {CVE_OPTIONS.map((option) => (
            <Checkbox key={option.value} value={option.value} className="iis-msf-option">
              <Space direction="vertical" size={2}>
                <Space size={6} wrap>
                  <Text strong>{option.value}</Text>
                  <SeverityTag severity={option.severity} />
                </Space>
                <Text type="secondary">{option.title} | {option.port}</Text>
              </Space>
            </Checkbox>
          ))}
        </Checkbox.Group>

        <Divider style={{ margin: '14px 0 10px' }} />
        <Space size={6} className="msf-footnote" wrap>
          <SafetyCertificateOutlined />
          <span>Focused scan for 4 critical CVEs on IIS/HTTP.sys/Web Deploy/WSUS</span>
        </Space>
      </div>
    </div>
  )
}

function PanelTitle() {
  return (
    <Space size={8}>
      <BugOutlined style={{ color: '#0f766e' }} />
      <Text strong>IIS Critical CVE Audit Controls</Text>
    </Space>
  )
}

function SectionTitle({ children }) {
  return <Text strong className="iis-msf-section-title">{children}</Text>
}

function SeverityTag({ severity }) {
  return <Tag color={severity === 'CRITICAL' ? 'red' : 'orange'}>{severity}</Tag>
}
