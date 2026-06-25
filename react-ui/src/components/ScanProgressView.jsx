import { Card, List, Progress, Space, Tag, Typography } from 'antd'
import { LoadingOutlined } from '@ant-design/icons'

function statusColor(status) {
  if (status === 'PASS') return 'green'
  if (status === 'FAIL' || status === 'ERROR') return 'volcano'
  if (status === 'MANUAL') return 'gold'
  if (status === 'RUNNING') return 'processing'
  return 'default'
}

export default function ScanProgressView({ progress }) {
  const total = Number(progress?.total || 0)
  const completed = Number(progress?.completed || 0)
  const percent = Number(progress?.percent || 0)
  const currentRule = progress?.currentRule
  const recentRules = Array.isArray(progress?.recentRules) ? progress.recentRules : []

  return (
    <Card className="glass-card scan-progress-card" title="Scanning configuration rules">
      <Space direction="vertical" size="middle" className="stage-shell">
        <section className="scan-progress-summary">
          <Progress
            type="circle"
            percent={percent}
            size={112}
            status={progress?.status === 'failed' ? 'exception' : 'active'}
          />
          <div className="scan-progress-copy">
            <Typography.Title level={4}>Scan in progress</Typography.Title>
            <Typography.Text type="secondary">
              {completed}/{total || '?'} rules scanned
            </Typography.Text>
            {currentRule ? (
              <div className="scan-current-rule">
                <Space size={8} wrap>
                  <LoadingOutlined />
                  <Tag color={statusColor(currentRule.status)}>{currentRule.status || 'RUNNING'}</Tag>
                  <Typography.Text strong>{currentRule.ruleId || '-'}</Typography.Text>
                </Space>
                <Typography.Text type="secondary">{currentRule.service || '-'}</Typography.Text>
                <Typography.Text>{currentRule.title || '-'}</Typography.Text>
              </div>
            ) : (
              <Typography.Text type="secondary">Preparing rule engine...</Typography.Text>
            )}
          </div>
        </section>

        <List
          size="small"
          bordered
          className="scan-progress-list"
          dataSource={recentRules}
          locale={{ emptyText: 'Rules will appear here as they finish.' }}
          renderItem={(item) => (
            <List.Item>
              <div className="scan-progress-row">
                <Space size={8} wrap>
                  <Tag color={statusColor(item.status)}>{item.status || 'DONE'}</Tag>
                  <Typography.Text strong>{item.ruleId || '-'}</Typography.Text>
                  <Typography.Text type="secondary">{item.service || '-'}</Typography.Text>
                </Space>
                <Typography.Text className="scan-progress-title">{item.title || '-'}</Typography.Text>
              </div>
            </List.Item>
          )}
        />
      </Space>
    </Card>
  )
}
