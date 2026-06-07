import { Descriptions, Modal, Space, Tag, Typography } from 'antd'
import { CategoryLabel, StatusTag } from './IisMsfStatus'

export default function IisMsfDetailModal({ row, onClose }) {
  return (
    <Modal open={Boolean(row)} onCancel={onClose} footer={null} width={800} title={row ? <Title row={row} /> : null}>
      {row ? (
        <Descriptions bordered size="small" column={1} labelStyle={{ width: 175 }}>
          <Descriptions.Item label="Status"><StatusTag status={row.status} /></Descriptions.Item>
          <Descriptions.Item label="Module Path"><CodeText value={row.module} /></Descriptions.Item>
          <Descriptions.Item label="Category"><CategoryLabel category={row.category} /></Descriptions.Item>
          <Descriptions.Item label="Risk">{(row.risk || '').replace(/_/g, ' ') || '-'}</Descriptions.Item>
          <Descriptions.Item label="CVEs"><CveList cves={row.cve} /></Descriptions.Item>
          <Descriptions.Item label="Port / SSL">{row.port} {row.ssl ? '(HTTPS)' : '(HTTP)'}</Descriptions.Item>
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

function Paragraph({ value, warn = false }) {
  return (
    <Typography.Paragraph className={warn ? 'msf-warning-text' : ''} style={{ marginBottom: 0, whiteSpace: 'pre-wrap' }}>
      {value || '-'}
    </Typography.Paragraph>
  )
}
