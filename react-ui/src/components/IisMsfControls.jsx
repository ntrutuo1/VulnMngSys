import { Alert, Button, Checkbox, Col, Divider, Input, Row, Space, Typography } from 'antd'
import { BugOutlined, CloseCircleFilled, PlayCircleOutlined, SafetyCertificateOutlined, StopOutlined } from '@ant-design/icons'

const { Text } = Typography

const SERVICE_OPTIONS = [
  { value: 'iis', title: 'IIS', detail: 'IIS / HTTP.sys / WebDAV / Web Deploy / WSUS' },
  { value: 'smb', title: 'SMB', detail: 'SMB, EternalBlue, Windows file sharing' },
  { value: 'rdp', title: 'RDP', detail: 'Remote Desktop / Terminal Services' },
  { value: 'winrm', title: 'WinRM', detail: 'Windows Remote Management / WSMan' },
  { value: 'active_directory', title: 'Active Directory', detail: 'AD, Kerberos, Netlogon, AD CS' },
  { value: 'exchange', title: 'Exchange', detail: 'Exchange Server, OWA, ECP' },
  { value: 'mssql', title: 'MSSQL', detail: 'Microsoft SQL Server' },
  { value: 'windows', title: 'Windows Host', detail: 'Windows Server host-level CVEs' },
  { value: 'all', title: 'All Services', detail: 'All Windows Server CVE modules in local warehouse' },
]

export default function IisMsfControls({
  connected,
  target,
  selectedServices,
  loading,
  onTargetChange,
  onSelectedServicesChange,
  onRun,
  onStop,
}) {
  const canRun = selectedServices.length > 0

  return (
    <div className="glass-card ant-card ant-card-small iis-msf-controls-card">
      <div className="ant-card-head">
        <div className="ant-card-head-wrapper">
          <div className="ant-card-head-title"><PanelTitle /></div>
        </div>
      </div>
      <div className="ant-card-body">
        {!connected ? (
          <Alert
            type="warning"
            showIcon
            icon={<CloseCircleFilled />}
            message="Metasploit RPC is not ready"
            description="Service Scan requires Metasploit RPC to execute module checks."
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
              type={loading ? 'default' : 'primary'}
              danger={loading}
              icon={loading ? <StopOutlined /> : <PlayCircleOutlined />}
              disabled={!canRun}
              onClick={loading ? onStop : onRun}
            >
              {loading ? 'Stop Scan' : 'Run Service Scan'}
            </Button>
          </Col>
        </Row>

        <Divider style={{ margin: '14px 0' }} />
        <SectionTitle>Service Selection</SectionTitle>
        <Checkbox.Group value={selectedServices} onChange={onSelectedServicesChange} disabled={loading} className="iis-msf-option-grid">
          {SERVICE_OPTIONS.map((option) => (
            <Checkbox key={option.value} value={option.value} className="iis-msf-option">
              <Space direction="vertical" size={0}>
                <Text strong>{option.title}</Text>
                <Text type="secondary">{option.detail}</Text>
              </Space>
            </Checkbox>
          ))}
        </Checkbox.Group>

        <Divider style={{ margin: '14px 0 10px' }} />
        <Space size={6} className="msf-footnote" wrap>
          <SafetyCertificateOutlined />
          <span>Ports and datastore values are module options; this screen selects service/module scope.</span>
        </Space>
      </div>
    </div>
  )
}

function PanelTitle() {
  return (
    <Space size={8}>
      <BugOutlined style={{ color: '#0f766e' }} />
      <Text strong>Service Scan Controls</Text>
    </Space>
  )
}

function SectionTitle({ children }) {
  return <Text strong className="iis-msf-section-title">{children}</Text>
}
