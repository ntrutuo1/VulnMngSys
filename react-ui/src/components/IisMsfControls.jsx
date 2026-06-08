import { Alert, Button, Card, Col, Divider, Input, Row, Space, Switch, Tooltip, Typography } from 'antd'
import { BugOutlined, CloseCircleFilled, PlayCircleOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons'

const { Text } = Typography

export default function IisMsfControls({
  connected,
  target,
  activeTest,
  loading,
  onTargetChange,
  onActiveTestChange,
  onRun,
}) {
  return (
    <Card className="glass-card" size="small" title={<PanelTitle />}>
      {!connected ? (
        <Alert
          type="warning"
          showIcon
          icon={<CloseCircleFilled />}
          message="Metasploit RPC is not ready"
          description="The audit scan is enabled after the backend installs Metasploit if needed and starts local msfrpcd."
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <Row gutter={[16, 12]} align="middle" wrap>
        <Col>
          <Space align="center">
            <Text type="secondary">Target:</Text>
            <Input value={target} onChange={(e) => onTargetChange(e.target.value)} style={{ width: 160 }} disabled={!connected} />
          </Space>
        </Col>
        <Col>
          <Tooltip title="Writes a benign test file to the web root. Only use in your own lab environment.">
            <Space align="center">
              <Switch size="small" checked={activeTest} onChange={onActiveTestChange} disabled={!connected} />
              <Text type="secondary">Active Test (PUT write)</Text>
            </Space>
          </Tooltip>
        </Col>
        <Col>
          <Button
            type="primary"
            icon={loading ? <ReloadOutlined spin /> : <PlayCircleOutlined />}
            loading={loading}
            disabled={!connected}
            onClick={onRun}
          >
            Run IIS MSF Audit
          </Button>
        </Col>
      </Row>
      <Divider style={{ margin: '14px 0 10px' }} />
      <Space size={6} className="msf-footnote">
        <SafetyCertificateOutlined />
        <span>Safe mode excludes DoS and memory-dump modules</span>
        <span>·</span>
        <span>Auxiliary scanners target IIS / HTTP.sys on Windows Server 2022+</span>
      </Space>
    </Card>
  )
}

function PanelTitle() {
  return (
    <Space size={8}>
      <BugOutlined style={{ color: '#0f766e' }} />
      <Text strong>IIS MSF Audit Controls</Text>
    </Space>
  )
}
