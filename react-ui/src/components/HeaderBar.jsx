import { Badge, Segmented, Space, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

export default function HeaderBar({ statusOk }) {
  const { t, i18n } = useTranslation()

  function handleLanguageChange(value) {
    i18n.changeLanguage(value)
  }

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
          <Segmented
            options={[
              { label: t('language.vi'), value: 'vi' },
              { label: t('language.en'), value: 'en' },
            ]}
            value={i18n.language === 'en' ? 'en' : 'vi'}
            onChange={handleLanguageChange}
            size="small"
          />
        </Space>
      </Space>
    </div>
  )
}
