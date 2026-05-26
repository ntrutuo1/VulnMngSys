import { Badge, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

export default function HeaderBar({ statusOk }) {
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
        <Space size={8}>
          <Typography.Text type="secondary">{t('language.label')}</Typography.Text>
          <Typography.Text strong>{t('language.en')}</Typography.Text>
        </Space>
      </Space>
    </div>
  )
}
