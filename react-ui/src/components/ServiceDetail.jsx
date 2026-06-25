import { Progress, Space, Tag, Typography } from 'antd'
import ResultTable from './ResultTable'
import { compliance, flattenGroupItems, groupStatus } from './serviceGroups'

function statusTag(group) {
  const status = groupStatus(group)
  if (status === 'fail') return <Tag color="volcano">Needs attention</Tag>
  if (status === 'manual') return <Tag color="gold">Manual review</Tag>
  return <Tag color="green">All passing</Tag>
}

export default function ServiceDetail({
  group,
  compact,
  selectedRuleIds,
  onSelectedRuleIdsChange,
}) {
  const items = flattenGroupItems(group)
  const score = compliance(group)

  return (
    <div className="service-detail">
      <section className="service-detail-head">
        <div>
          <Space size={8} wrap>
            <Typography.Title level={3}>{group?.label || group?.serviceId || 'Service'}</Typography.Title>
            {statusTag(group)}
          </Space>
          <Typography.Text type="secondary">
            {group?.passed || 0}/{group?.total || 0} passed, {group?.failed || 0} failed, {group?.manual || 0} manual
          </Typography.Text>
        </div>
        <Progress
          percent={score}
          strokeColor={(group?.failed || 0) > 0 ? '#dc2626' : '#16a34a'}
          className="service-detail-progress"
        />
      </section>
      <ResultTable
        items={items}
        compact={compact}
        selectedRuleIds={selectedRuleIds}
        onSelectedRuleIdsChange={onSelectedRuleIdsChange}
      />
    </div>
  )
}
