import { Badge, Segmented, Space, Typography } from 'antd'
import { DesktopOutlined, MobileOutlined } from '@ant-design/icons'
import { useTranslation } from 'react-i18next'

export default function HeaderBar({ statusOk, viewMode, onViewModeChange }) {
  const { t } = useTranslation()

  return (
    <div className="header-bar">
      <div>
        <Typography.Title level={2} style={{ margin: 0 }}>
          {t('app.title')}
        </Typography.Title>
        <Typography.Text type="secondary">
          {t('app.subtitle')}
        </Typography.Text>
      </div>
      <Space direction="vertical" size={8} className="header-actions">
        <Badge
          status={statusOk ? 'success' : 'error'}
          text={statusOk ? t('app.statusReady') : t('app.statusNotReady')}
        />
        <Segmented
          size="small"
          value={viewMode}
          onChange={onViewModeChange}
          options={[
            { label: t('view.desktop'), value: 'desktop', icon: <DesktopOutlined /> },
            { label: t('view.mobile'), value: 'mobile', icon: <MobileOutlined /> },
          ]}
        />
      </Space>
    </div>
  )
}
