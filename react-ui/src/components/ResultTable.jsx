import { useMemo, useState } from 'react'
import { Button, Descriptions, Modal, Space, Table, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import './ResultTable.css'

function verdictColor(verdict) {
  return verdict === 'PASS' ? 'green' : 'volcano'
}

export default function ResultTable({ items = [], compact = false }) {
  const { t } = useTranslation()
  const [selectedRow, setSelectedRow] = useState(null)

  const pagination = {
    pageSize: 20,
    showSizeChanger: true,
    pageSizeOptions: ['10', '20', '50', '100'],
    showTotal: (total, range) => t('table.totalRules', { from: range[0], to: range[1], total }),
  }

  const safeItems = useMemo(() => items || [], [items])

  function openDetails(record) {
    setSelectedRow(record)
  }

  function closeDetails() {
    setSelectedRow(null)
  }

  const columns = [
    {
      title: t('table.rule'),
      dataIndex: 'ruleId',
      key: 'ruleId',
      width: '25%',
      render: (value, row) => (
        <button
          type="button"
          className="result-rule-cell"
          onClick={(event) => {
            event.stopPropagation()
            openDetails(row)
          }}
        >
          <Typography.Text strong className="result-rule-id" ellipsis={{ tooltip: value || row.rule_id || '-' }}>
            {value || row.rule_id || '-'}
          </Typography.Text>
          <Typography.Text type="secondary" className="result-rule-title" ellipsis={{ tooltip: row.title || '-' }}>
            {row.title || '-'}
          </Typography.Text>
        </button>
      ),
    },
    {
      title: t('table.result'),
      dataIndex: 'verdict',
      key: 'verdict',
      width: '8%',
      render: (value) => <Tag color={verdictColor(value)}>{value || 'FAIL'}</Tag>,
    },
    {
      title: t('table.expected'),
      dataIndex: 'expected',
      key: 'expected',
      width: '20%',
      responsive: compact ? ['lg'] : undefined,
      ellipsis: true,
      render: (value) => <Typography.Text ellipsis={{ tooltip: value || '-' }}>{value || '-'}</Typography.Text>,
    },
    {
      title: t('table.actual'),
      dataIndex: 'actual',
      key: 'actual',
      width: '20%',
      responsive: compact ? ['md'] : undefined,
      ellipsis: true,
      render: (value) => <Typography.Text ellipsis={{ tooltip: value || '-' }}>{value || '-'}</Typography.Text>,
    },
    {
      title: t('table.status'),
      dataIndex: 'status',
      key: 'status',
      width: '8%',
      responsive: compact ? ['lg'] : undefined,
    },
    {
      title: t('table.guidance'),
      dataIndex: 'guidance',
      key: 'guidance',
      width: '15%',
      responsive: compact ? ['xl'] : undefined,
      ellipsis: true,
      render: (value) => {
        const guidance = Array.isArray(value) ? value : []
        if (guidance.length === 0) {
          return <Typography.Text type="secondary">-</Typography.Text>
        }
        return <Typography.Text ellipsis={{ tooltip: guidance.join('\n') }}>{guidance.join(' • ')}</Typography.Text>
      },
    },
    {
      title: '',
      key: 'action',
      width: '4%',
      render: (_, row) => (
        <Button
          type="link"
          onClick={(event) => {
            event.stopPropagation()
            openDetails(row)
          }}
        >
          {t('table.details')}
        </Button>
      ),
    },
  ]

  return (
    <>
      <Table
        rowKey={(record, index) => `${record.ruleId || record.rule_id || record.title || 'row'}-${index}`}
        columns={columns}
        dataSource={safeItems}
        pagination={pagination}
        size="small"
        // Use fixed table layout and 100% width so percent column widths are respected
        tableLayout="fixed"
        scroll={{ x: compact ? 520 : 900 }}
        style={{ width: '100%' }}
        onRow={(record) => ({
          onClick: () => openDetails(record),
          style: { cursor: 'pointer' },
        })}
      />

      <Modal
        open={Boolean(selectedRow)}
        onCancel={closeDetails}
        footer={null}
        width={920}
        className="rule-details-modal"
        title={selectedRow ? `${selectedRow.ruleId || selectedRow.rule_id || '-'} · ${selectedRow.title || '-'}` : t('table.details')}
      >
        {selectedRow ? (
          <Descriptions bordered size="small" column={1} labelStyle={{ width: 200 }}>
            <Descriptions.Item label={t('table.rule')}>
              <Space direction="vertical" size={0}>
                <Typography.Text strong>{selectedRow.ruleId || selectedRow.rule_id || '-'}</Typography.Text>
                <Typography.Text type="secondary">{selectedRow.title || '-'}</Typography.Text>
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label={t('table.result')}>
              <Tag color={verdictColor(selectedRow.verdict)}>{selectedRow.verdict || 'FAIL'}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label={t('table.expected')}>{selectedRow.expected || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.actual')}>{selectedRow.actual || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.status')}>{selectedRow.status || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.service')}>{selectedRow.serviceName || selectedRow.service_name || selectedRow.service || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.checkType')}>{selectedRow.checkType || selectedRow.check_type || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.source')}>{selectedRow.source || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.registryPath')}>{selectedRow.registry_path || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.powershellCheck')}>
              <Typography.Paragraph style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }} copyable>
                {selectedRow.powershell_check || '-'}
              </Typography.Paragraph>
            </Descriptions.Item>
            <Descriptions.Item label={t('table.remediation')}>
              <Typography.Paragraph style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>
                {selectedRow.remediation || '-'}
              </Typography.Paragraph>
            </Descriptions.Item>
            <Descriptions.Item label={t('table.reason')}>
              <Typography.Paragraph style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>
                {selectedRow.reason || '-'}
              </Typography.Paragraph>
            </Descriptions.Item>
            <Descriptions.Item label={t('table.guidance')}>
              {Array.isArray(selectedRow.guidance) && selectedRow.guidance.length > 0 ? (
                <Space direction="vertical" style={{ width: '100%' }}>
                  {selectedRow.guidance.map((line, index) => (
                    <Typography.Text key={`${line}-${index}`}>{line}</Typography.Text>
                  ))}
                </Space>
              ) : (
                <Typography.Text type="secondary">-</Typography.Text>
              )}
            </Descriptions.Item>
          </Descriptions>
        ) : null}
      </Modal>
    </>
  )
}
