import { Card, Col, Row, Statistic, Tag } from 'antd'
import { useTranslation } from 'react-i18next'

export default function StatusCards({ inventory }) {
  const { t } = useTranslation()

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} md={6}>
        <Card>
          <Statistic title={t('cards.osTitle')} value={inventory?.osCaption || t('cards.unknown')} />
          <div style={{ marginTop: 8 }}>
            <Tag color="geekblue">{inventory?.profileKey || inventory?.osVersion || 'N/A'}</Tag>
            <Tag color={inventory?.isServer ? 'green' : 'orange'}>
              {inventory?.isServer ? 'Windows Server' : t('cards.notServer')}
            </Tag>
          </div>
        </Card>
      </Col>
      <Col xs={24} md={6}>
        <Card>
          <Statistic title={t('cards.serviceTitle')} value={inventory?.detectedServiceCount || 0} />
        </Card>
      </Col>
    </Row>
  )
}
