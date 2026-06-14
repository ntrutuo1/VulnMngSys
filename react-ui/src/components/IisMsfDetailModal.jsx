import { Descriptions, Modal, Space, Tag, Typography } from 'antd'
import { CategoryLabel, StatusTag } from './IisMsfStatus'

export default function IisMsfDetailModal({ row, onClose }) {
  return (
    <Modal open={Boolean(row)} onCancel={onClose} footer={null} width={800} title={row ? <Title row={row} /> : null}>
      {row ? (
        <Descriptions bordered size="small" column={1} labelStyle={{ width: 175 }}>
          <Descriptions.Item label="Status"><StatusTag status={row.status} /></Descriptions.Item>
          <Descriptions.Item label="Severity"><SeverityTag severity={row.severity} cvss={row.cvss} /></Descriptions.Item>
          <Descriptions.Item label="Module Path"><CodeText value={row.module} /></Descriptions.Item>
          <Descriptions.Item label="Check Method">{(row.check_method || '').replace(/_/g, ' ') || '-'}</Descriptions.Item>
          <Descriptions.Item label="Category"><CategoryLabel category={row.category} /></Descriptions.Item>
          <Descriptions.Item label="Risk">{(row.risk || '').replace(/_/g, ' ') || '-'}</Descriptions.Item>
          <Descriptions.Item label="CVEs"><CveList cves={row.cve} /></Descriptions.Item>
          <Descriptions.Item label="Port / SSL">{row.port} {row.ssl ? '(HTTPS)' : '(HTTP)'}</Descriptions.Item>
          <Descriptions.Item label="Local Check"><LocalCheck local={row.local_check_result} /></Descriptions.Item>
          <Descriptions.Item label="MSF Checks"><MsfChecks items={row.msf_results} /></Descriptions.Item>
          <Descriptions.Item label="Expected Signal">{row.expected_signal || '-'}</Descriptions.Item>
          <Descriptions.Item label="Evidence"><Paragraph value={row.evidence} warn /></Descriptions.Item>
          <Descriptions.Item label="Remediation"><Paragraph value={row.remediation} /></Descriptions.Item>
          <Descriptions.Item label="Server Context">{row.server_2022_relevance || '-'}</Descriptions.Item>
        </Descriptions>
      ) : null}
    </Modal>
  )
}

function Title({ row }) {
  return (
    <Space>
      <Typography.Text code>{row.id}</Typography.Text>
      <Typography.Text strong>{row.name}</Typography.Text>
    </Space>
  )
}

function CodeText({ value }) {
  return <Typography.Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>{value}</Typography.Text>
}

function CveList({ cves = [] }) {
  if (!cves.length) return <Typography.Text type="secondary">None listed</Typography.Text>
  return (
    <Space wrap>
      {cves.map((cve) => <Tag key={cve} color="blue">{cve}</Tag>)}
    </Space>
  )
}

function SeverityTag({ severity, cvss }) {
  const value = String(severity || '').toUpperCase()
  return (
    <Space>
      <Tag color={value === 'CRITICAL' ? 'red' : 'orange'}>{value || '-'}</Tag>
      {cvss ? <Typography.Text type="secondary">CVSS {cvss}</Typography.Text> : null}
    </Space>
  )
}

function LocalCheck({ local }) {
  if (!local) return <Typography.Text type="secondary">-</Typography.Text>
  const hotfixes = local.hotfixes?.map((item) => item.HotFixID).filter(Boolean) || []
  return (
    <Space direction="vertical" size={4} style={{ width: '100%' }}>
      <StatusTag status={local.status || 'INFO'} />
      <Paragraph value={local.evidence} warn={local.status === 'FAIL'} />
      <Typography.Text type="secondary">
        Patch baseline: {local.patch_after || '-'} | HotFixes: {hotfixes.length ? hotfixes.join(', ') : '-'}
      </Typography.Text>
    </Space>
  )
}

function MsfChecks({ items = [] }) {
  if (!items.length) return <Typography.Text type="secondary">No MSF module was executed.</Typography.Text>
  return (
    <Space direction="vertical" size={4} style={{ width: '100%' }}>
      {items.map((item) => (
        <Space key={`${item.port}-${item.ssl}`} wrap>
          <Typography.Text code>{item.port}{item.ssl ? ' TLS' : ''}</Typography.Text>
          <StatusTag status={item.status || 'INFO'} />
          <Typography.Text type="secondary">{item.evidence || '-'}</Typography.Text>
        </Space>
      ))}
    </Space>
  )
}

function Paragraph({ value, warn = false }) {
  return (
    <Typography.Paragraph className={warn ? 'msf-warning-text' : ''} style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>
      {value || '-'}
    </Typography.Paragraph>
  )
}
