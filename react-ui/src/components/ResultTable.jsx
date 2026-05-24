import { Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

function verdictColor(verdict) {
  return verdict === 'PASS' ? 'green' : 'volcano'
}

export default function ResultTable({ items = [] }) {
  const { t } = useTranslation()

  const pagination = {
    pageSize: 20,
    showSizeChanger: true,
    pageSizeOptions: ['10', '20', '50', '100'],
    showTotal: (total, range) => t('table.totalRules', { from: range[0], to: range[1], total }),
  }

  const columns = [
    {
      title: 'Rule',
      dataIndex: 'ruleId',
      key: 'ruleId',
      width: 140,
      render: (value, row) => (
        <div>
          <Typography.Text strong>{value || row.rule_id || '-'}</Typography.Text>
          <div>
            <Typography.Text type="secondary">{row.title || '-'}</Typography.Text>
          </div>
        </div>
      ),
    },
    {
      title: t('table.result'),
      dataIndex: 'verdict',
      key: 'verdict',
      width: 100,
      render: (value) => <Tag color={verdictColor(value)}>{value || 'FAIL'}</Tag>,
    },
    {
      title: 'Expected',
      dataIndex: 'expected',
      key: 'expected',
      width: 220,
    },
    {
      title: 'Actual',
      dataIndex: 'actual',
      key: 'actual',
      width: 220,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 160,
    },
    {
      title: 'Guidance',
      dataIndex: 'guidance',
      key: 'guidance',
      render: (value) => {
        const guidance = Array.isArray(value) ? value : []
        if (guidance.length === 0) {
          return <Typography.Text type="secondary">-</Typography.Text>
        }
        return guidance.map((line) => <div key={line}>{line}</div>)
      },
    },
  ]

  return <Table rowKey={(record, index) => `${record.ruleId || record.rule_id || record.title || 'row'}-${index}`} columns={columns} dataSource={items} pagination={pagination} size="small" />
}