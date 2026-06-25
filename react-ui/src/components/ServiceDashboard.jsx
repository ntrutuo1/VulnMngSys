import { Card, Empty, Progress, Segmented, Space, Switch, Typography } from 'antd'
import { useMemo, useState } from 'react'
import { compliance, groupStatus, summarizeGroups } from './serviceGroups'

function strokeColor(group) {
  const status = groupStatus(group)
  if (status === 'fail') return '#dc2626'
  if (status === 'manual') return '#d97706'
  return '#16a34a'
}

export default function ServiceDashboard({ groups = [], onSelect }) {
  const [failingOnly, setFailingOnly] = useState(false)
  const [view, setView] = useState('all')
  const summary = useMemo(() => summarizeGroups(groups), [groups])
  const visibleGroups = useMemo(() => {
    return groups.filter((group) => {
      if (failingOnly && Number(group.failed || 0) === 0) return false
      if (view === 'root' && group.category === 'folder') return false
      if (view === 'folder' && group.category !== 'folder') return false
      return true
    })
  }, [groups, failingOnly, view])

  return (
    <div className="service-dashboard">
      <section className="compliance-summary">
        <div>
          <Typography.Title level={3}>Compliance Score</Typography.Title>
          <Typography.Text type="secondary">
            {summary.passed}/{summary.total} passed, {summary.failed} failed, {summary.manual} manual
          </Typography.Text>
        </div>
        <Progress
          type="circle"
          percent={summary.compliance}
          size={108}
          strokeColor={summary.failed > 0 ? '#dc2626' : '#16a34a'}
        />
      </section>

      <div className="service-filters">
        <Space>
          <Switch checked={failingOnly} onChange={setFailingOnly} />
          <Typography.Text>Failing services</Typography.Text>
        </Space>
        <Segmented
          value={view}
          onChange={setView}
          options={[
            { label: 'All', value: 'all' },
            { label: 'Root', value: 'root' },
            { label: 'Folders', value: 'folder' },
          ]}
        />
      </div>

      {visibleGroups.length > 0 ? (
        <div className="service-card-grid">
          {visibleGroups.map((group) => (
            <Card
              key={group.serviceId}
              hoverable
              className="service-card"
              onClick={() => onSelect(group.serviceId)}
            >
              <div className="service-card-inner">
                <Progress
                  type="circle"
                  percent={compliance(group)}
                  size={64}
                  strokeColor={strokeColor(group)}
                />
                <div className="service-card-copy">
                  <Typography.Text strong>{group.label || group.serviceId}</Typography.Text>
                  <Typography.Text type="secondary">
                    {group.passed || 0}/{group.total || 0} passed
                  </Typography.Text>
                  <Typography.Text className={group.failed > 0 ? 'service-card-failed' : 'service-card-ok'}>
                    {group.failed || 0} failed
                  </Typography.Text>
                </div>
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
      )}
    </div>
  )
}
