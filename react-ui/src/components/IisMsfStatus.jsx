import { Tag, Typography } from 'antd'
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  ExclamationCircleOutlined,
  InfoCircleOutlined,
  MinusCircleOutlined,
  WarningOutlined,
} from '@ant-design/icons'

export const STATUS_ANT_COLOR = {
  PASS: 'success',
  FAIL: 'error',
  WARNING: 'warning',
  INFO: 'processing',
  SKIPPED: 'default',
  ERROR: 'volcano',
}

const STATUS_ICON = {
  PASS: <CheckCircleOutlined />,
  FAIL: <CloseCircleOutlined />,
  WARNING: <ExclamationCircleOutlined />,
  INFO: <InfoCircleOutlined />,
  SKIPPED: <MinusCircleOutlined />,
  ERROR: <WarningOutlined />,
}

export function StatusTag({ status }) {
  return (
    <Tag icon={STATUS_ICON[status] || null} color={STATUS_ANT_COLOR[status] || 'default'} className="msf-status-tag">
      {status}
    </Tag>
  )
}

export function CategoryLabel({ category }) {
  const label = (category || '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())
  return (
    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
      {label}
    </Typography.Text>
  )
}
