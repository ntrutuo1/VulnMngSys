import { useMemo, useState } from 'react'
import { Button, Space, Table, Tag, Tooltip, Typography } from 'antd'
import IisMsfDetailModal from './IisMsfDetailModal'
import { CategoryLabel, STATUS_ANT_COLOR, StatusTag } from './IisMsfStatus'

export default function IisMsfResultTable({ items = [] }) {
  const [selectedRow, setSelectedRow] = useState(null)
  const columns = useMemo(() => buildColumns(setSelectedRow), [])

  return (
    <>
      <Table
        className="iis-msf-result-table"
        rowKey={(record, idx) => `${record.id || record.module_id || 'row'}-${idx}`}
        columns={columns}
        dataSource={items}
        pagination={false}
        size="small"
        tableLayout="fixed"
        scroll={{ x: 1240 }}
        style={{ width: '100%' }}
        onRow={(record) => ({ onClick: () => setSelectedRow(record), style: { cursor: 'pointer' } })}
        rowClassName={(record) => {
          if (record.status === 'FAIL') return 'msf-row-fail'
          if (record.status === 'WARNING') return 'msf-row-warning'
          return ''
        }}
      />
      <IisMsfDetailModal row={selectedRow} onClose={() => setSelectedRow(null)} />
    </>
  )
}

function buildColumns(setSelectedRow) {
  return [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 110,
      render: (value) => <Typography.Text code className="nowrap">{value}</Typography.Text>,
    },
    {
      title: 'CVE',
      dataIndex: 'cve',
      key: 'cve',
      width: 150,
      render: (value) => <CveList cves={value} />,
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 104,
      render: (value) => <SeverityTag severity={value} />,
    },
    {
      title: 'Module / Name',
      dataIndex: 'name',
      key: 'name',
      width: 260,
      render: (value, row) => <ModuleName value={value} module={row.module} />,
    },
    {
      title: 'Category',
      dataIndex: 'category',
      key: 'category',
      width: 180,
      render: (value) => <CategoryLabel category={value} />,
    },
    {
      title: 'Port',
      dataIndex: 'port',
      key: 'port',
      width: 70,
      render: (value, row) => <Typography.Text>{value}{row.ssl ? ' TLS' : ''}</Typography.Text>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 114,
      filters: Object.keys(STATUS_ANT_COLOR).map((status) => ({ text: status, value: status })),
      onFilter: (value, record) => record.status === value,
      render: (value) => <StatusTag status={value} />,
    },
    {
      title: 'Local Check',
      dataIndex: 'local_check_result',
      key: 'local_check_result',
      width: 138,
      render: (value) => <LocalCheck value={value} />,
    },
    {
      title: 'Evidence',
      dataIndex: 'evidence',
      key: 'evidence',
      width: 300,
      ellipsis: true,
      render: (value) => <Evidence value={value} />,
    },
    {
      title: '',
      key: 'action',
      width: 76,
      render: (_, row) => <DetailsButton row={row} onSelect={setSelectedRow} />,
    },
  ]
}

function CveList({ cves = [] }) {
  if (!cves.length) return <Typography.Text type="secondary">-</Typography.Text>
  return (
    <Space size={4} wrap>
      {cves.map((cve) => <Typography.Text key={cve} code className="nowrap">{cve}</Typography.Text>)}
    </Space>
  )
}

function SeverityTag({ severity }) {
  const value = String(severity || '').toUpperCase()
  return <Tag color={value === 'CRITICAL' ? 'red' : 'orange'}>{value || '-'}</Tag>
}

function ModuleName({ value, module }) {
  return (
    <Space direction="vertical" size={2}>
      <Typography.Text strong ellipsis={{ tooltip: value }}>{value}</Typography.Text>
      <Typography.Text type="secondary" className="monospace-small" ellipsis={{ tooltip: module }}>{module}</Typography.Text>
    </Space>
  )
}

function LocalCheck({ value }) {
  if (!value) return <Typography.Text type="secondary">-</Typography.Text>
  return (
    <Tooltip title={value.evidence || ''} placement="topLeft">
      <span><StatusTag status={value.status || 'INFO'} /></span>
    </Tooltip>
  )
}

function Evidence({ value }) {
  if (!value) return <Typography.Text type="secondary">-</Typography.Text>
  return (
    <Tooltip title={value} placement="topLeft">
      <Typography.Text className="msf-warning-text evidence-cell-text" ellipsis>{value}</Typography.Text>
    </Tooltip>
  )
}

function DetailsButton({ row, onSelect }) {
  return (
    <Button
      type="link"
      size="small"
      className="compact-link"
      onClick={(event) => {
        event.stopPropagation()
        onSelect(row)
      }}
    >
      Details
    </Button>
  )
}
