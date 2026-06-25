import { useEffect, useMemo, useState } from 'react'
import { Button, Descriptions, Drawer, Space, Table, Tabs, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'
import './ResultTable.css'

function verdictColor(verdict) {
  if (verdict === 'PASS') return 'green'
  if (verdict === 'MANUAL') return 'gold'
  return 'volcano'
}

function ruleId(record) {
  return record.ruleId || record.rule_id || record.id || record.title || ''
}

function verdictOf(record) {
  return (record.verdict || (record.passed ? 'PASS' : 'FAIL') || 'FAIL').toUpperCase()
}

function currentHashTarget() {
  const raw = window.location.hash || ''
  const match = raw.match(/^#rule\/(.+)$/)
  return match ? decodeURIComponent(match[1]) : ''
}

export default function ResultTable({ items = [], compact = false, selectedRuleIds = [], onSelectedRuleIdsChange }) {
  const { t } = useTranslation()
  const [selectedRow, setSelectedRow] = useState(null)
  const [hashTarget, setHashTarget] = useState(() => currentHashTarget())

  const pagination = {
    pageSize: 20,
    showSizeChanger: true,
    pageSizeOptions: ['10', '20', '50', '100'],
    showTotal: (total, range) => t('table.totalRules', { from: range[0], to: range[1], total }),
  }

  const safeItems = useMemo(() => items || [], [items])
  const groupedItems = useMemo(() => {
    const failed = []
    const passed = []
    const manual = []
    for (const item of safeItems) {
      const verdict = verdictOf(item)
      if (verdict === 'PASS') passed.push(item)
      else if (verdict === 'MANUAL') manual.push(item)
      else failed.push(item)
    }
    return { failed, passed, manual }
  }, [safeItems])

  const selectedKeys = useMemo(() => {
    const selected = new Set(selectedRuleIds)
    return groupedItems.failed.map((item) => ruleId(item)).filter((key) => selected.has(key))
  }, [groupedItems.failed, selectedRuleIds])
  const visibleFailedKeys = useMemo(
    () => groupedItems.failed.map((item) => ruleId(item)).filter(Boolean),
    [groupedItems.failed],
  )

  useEffect(() => {
    function onHashChange() {
      setHashTarget(currentHashTarget())
    }
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

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
      render: (value) => value,
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
        return <Typography.Text ellipsis={{ tooltip: guidance.join('\n') }}>{guidance.join(' | ')}</Typography.Text>
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

  function renderTable(dataSource, selectable = false) {
    const rowSelection = selectable && onSelectedRuleIdsChange ? {
      selectedRowKeys: selectedKeys,
      onChange: (_, selectedRows) => {
        const visible = new Set(visibleFailedKeys)
        const nextVisible = selectedRows.map((row) => ruleId(row)).filter(Boolean)
        const preserved = selectedRuleIds.filter((id) => !visible.has(id))
        onSelectedRuleIdsChange([...preserved, ...nextVisible])
      },
    } : undefined

    return (
      <Table
        rowKey={(record) => ruleId(record) || record.hash_id || record.hashId}
        rowSelection={rowSelection}
        columns={columns}
        dataSource={dataSource}
        pagination={selectable ? false : pagination}
        size="small"
        tableLayout="fixed"
        scroll={{ x: compact ? 560 : 940 }}
        style={{ width: '100%' }}
        rowClassName={(record) => {
          const rowHash = record.hash_id || record.hashId
          return rowHash && rowHash === hashTarget ? 'result-row-highlight' : ''
        }}
        onRow={(record) => ({
          onClick: () => openDetails(record),
          style: { cursor: 'pointer' },
        })}
      />
    )
  }

  return (
    <>
      <Tabs
        items={[
          {
            key: 'failed',
            label: t('table.failedTab', { count: groupedItems.failed.length }),
            children: renderTable(groupedItems.failed, true),
          },
          {
            key: 'passed',
            label: t('table.passedTab', { count: groupedItems.passed.length }),
            children: renderTable(groupedItems.passed),
          },
          {
            key: 'manual',
            label: t('table.manualTab', { count: groupedItems.manual.length }),
            children: renderTable(groupedItems.manual),
          },
        ]}
      />

      <Drawer
        open={Boolean(selectedRow)}
        onClose={closeDetails}
        width={compact ? '100%' : 720}
        className="rule-details-drawer"
        title={selectedRow ? `${selectedRow.ruleId || selectedRow.rule_id || '-'} - ${selectedRow.title || '-'}` : t('table.details')}
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
            <Descriptions.Item label={t('table.hashId')}>{selectedRow.hash_id || selectedRow.hashId || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.checkType')}>{selectedRow.checkType || selectedRow.check_type || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.source')}>{selectedRow.source || '-'}</Descriptions.Item>
            <Descriptions.Item label={t('table.cisReference')}>{selectedRow.cis_reference || selectedRow.cisReference || '-'}</Descriptions.Item>
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
      </Drawer>
    </>
  )
}
