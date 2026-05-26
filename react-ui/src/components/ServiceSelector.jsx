import { Button, Card, Checkbox, Empty, Row, Col, Space, Tag, Typography } from 'antd'
import { useTranslation } from 'react-i18next'

function getServiceName(service) {
  return String(service?.Name || service?.name || service?.DisplayName || service?.displayName || '').trim()
}

function getServiceLabel(service) {
  const name = getServiceName(service)
  const displayName = String(service?.DisplayName || service?.displayName || '').trim()
  const startType = String(service?.StartType || service?.startType || '').trim()
  const state = String(service?.State || service?.state || '').trim()

  return (
    <Space direction="vertical" size={2} className="service-option-copy">
      <Typography.Text strong className="service-option-title">
        {displayName || name || '-'}
      </Typography.Text>
      <Typography.Text type="secondary" className="service-option-subtitle">
        {name || '-'}
      </Typography.Text>
      <Space size={6} wrap>
        {state ? <Tag color="blue">{state}</Tag> : null}
        {startType ? <Tag color="geekblue">{startType}</Tag> : null}
      </Space>
    </Space>
  )
}

export default function ServiceSelector({ services = [], selectedServiceNames = [], onChange, loading = false }) {
  const { t } = useTranslation()

  const normalizedServices = services
    .map((service) => ({ ...service, serviceName: getServiceName(service) }))
    .filter((service) => Boolean(service.serviceName))

  const allSelected = normalizedServices.length > 0 && selectedServiceNames.length === normalizedServices.length
  const someSelected = selectedServiceNames.length > 0

  function handleSelectAll() {
    onChange(normalizedServices.map((service) => service.serviceName))
  }

  function handleClear() {
    onChange([])
  }

  return (
    <Card
      title={t('scan.servicesTitle')}
      className="glass-card"
      extra={
        <Space wrap>
          <Tag color="cyan">
            {t('scan.serviceCount', { selected: selectedServiceNames.length, total: normalizedServices.length })}
          </Tag>
          <Button size="small" onClick={handleSelectAll} disabled={loading || allSelected || normalizedServices.length === 0}>
            {t('scan.selectAll')}
          </Button>
          <Button size="small" onClick={handleClear} disabled={loading || !someSelected}>
            {t('scan.clearSelection')}
          </Button>
        </Space>
      }
    >
      {normalizedServices.length === 0 ? (
        <Empty description={t('scan.noServicesDetected')} />
      ) : (
        <>
          <Typography.Paragraph type="secondary" style={{ marginTop: 0 }}>
            {t('scan.servicesDescription')}
          </Typography.Paragraph>
          <Checkbox.Group value={selectedServiceNames} onChange={onChange} style={{ width: '100%' }}>
            <Row gutter={[12, 12]}>
              {normalizedServices.map((service) => (
                <Col key={service.serviceName} xs={24} sm={12} lg={8}>
                  <Checkbox value={service.serviceName} className="service-checkbox">
                    {getServiceLabel(service)}
                  </Checkbox>
                </Col>
              ))}
            </Row>
          </Checkbox.Group>
        </>
      )}
    </Card>
  )
}