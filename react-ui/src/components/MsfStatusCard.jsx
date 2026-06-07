import { Alert, Badge, Button, Card, Space, Typography } from 'antd'
import { ApiOutlined, ReloadOutlined } from '@ant-design/icons'

const { Text } = Typography

export default function MsfStatusCard({ status, loading, onRefresh }) {
  const connected = Boolean(status?.connected)
  const starting = Boolean(status?.starting)
  const installing = Boolean(status?.installing)
  const busy = starting || installing
  const badgeStatus = connected ? 'success' : busy ? 'processing' : 'error'
  const label = connected ? 'msfrpc connected' : installing ? 'Installing Metasploit' : starting ? 'Starting local msfrpcd' : 'msfrpc unavailable'

  return (
    <Card className="glass-card" size="small" title={<Title connected={connected} label={label} />}>
      <Space direction="vertical" size={12} style={{ width: '100%' }}>
        <Text type="secondary">
          The backend installs Metasploit when needed and starts a local hidden msfrpcd process for this app.
        </Text>
        <Space wrap>
          <Badge status={badgeStatus} text={<Text>{label}</Text>} />
          {status?.executable ? <Text type="secondary">Executable: {status.executable}</Text> : null}
        </Space>
        {!connected ? (
          <Alert
            type={busy ? 'info' : 'warning'}
            showIcon
            message={status?.message || 'Metasploit RPC is not ready yet.'}
          />
        ) : null}
        <Button icon={loading ? <ReloadOutlined spin /> : <ReloadOutlined />} onClick={onRefresh} loading={loading}>
          Refresh MSF status
        </Button>
      </Space>
    </Card>
  )
}

function Title({ connected, label }) {
  return (
    <Space size={8}>
      <ApiOutlined style={{ color: connected ? '#0f766e' : '#d97706' }} />
      <Text strong>Metasploit RPC</Text>
      <Badge status={connected ? 'success' : 'warning'} text={label} />
    </Space>
  )
}
