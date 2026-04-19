import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  ConfigProvider,
  Descriptions,
  Divider,
  Drawer,
  Grid,
  Input,
  Layout,
  List,
  Radio,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Steps,
  Table,
  Tag,
  Typography,
  theme,
} from 'antd';
import { moduleCatalog } from './catalog';

const { Header, Content } = Layout;
const { Title, Text, Paragraph } = Typography;
const { useBreakpoint } = Grid;
const { defaultAlgorithm } = theme;

const osOptions = ['all', 'linux', 'windows', 'macos'];
const serviceOptions = ['all', 'ssh', 'apache-http', 'apache-tomcat'];
const apacheLayoutOptions = ['auto', 'xampp', 'standalone'];
const stepLabels = ['Target', 'Module', 'Review', 'Result'];

function transformBackendResult(backendReport) {
  const rows = backendReport.results.map((result) => ({
    key: result.code,
    code: result.code,
    title: result.title,
    severity: result.severity,
    passed: result.passed,
    configLine: Number(result.config_line || 0),
    reason: result.reason,
    where: result.config_path
      ? `${result.config_path}${result.config_line ? `:${result.config_line}` : ''}`
      : 'N/A',
    expected: result.baseline || 'See Apache_HTTP_server.txt CIS baseline',
    observed: result.reason,
    actualLine: result.actual_line || '',
    suggestedLine: result.suggested_line || '',
    explanation: result.explanation || '',
    whyFail: result.reason,
    fixCommands: result.suggested_line
      ? [
          `Set in conf: ${result.suggested_line}`,
          'Reload Apache after applying changes.',
        ]
      : [],
    cisRef: 'CIS Apache HTTP Server 2.4 Benchmark v2.3.0',
  }));

  const cveAdvisories = (backendReport.cve_advisories || []).map((item) => ({
    cveId: item.cve_id,
    title: item.title,
    severity: item.severity,
    likelihood: item.likelihood || 'Thấp',
    reason: item.reason,
    reference: item.reference,
  }));

  const failedRows = rows.filter((item) => !item.passed && item.configLine > 0);

  const missingDirectiveSuggestions = rows
    .filter((item) => !item.passed && item.configLine === 0 && item.suggestedLine)
    .map((item) => ({
      code: item.code,
      title: item.title,
      where: item.where,
      suggestedLine: item.suggestedLine,
    }));

  return {
    hardeningIndex: backendReport.summary.hardening_index,
    grade: backendReport.summary.grade,
    passedChecks: backendReport.summary.passed_checks,
    totalChecks: backendReport.summary.total_checks,
    failedChecks: backendReport.summary.failed_checks,
    rows,
    failedRows,
    overallSuggestions: missingDirectiveSuggestions,
    warnings: backendReport.summary.warnings || [],
    cveAdvisories,
  };
}

export default function App() {
  const screens = useBreakpoint();
  const [osFamily, setOsFamily] = useState('windows');
  const [service, setService] = useState('ssh');
  const [selectedId, setSelectedId] = useState('');
  const [osVersion, setOsVersion] = useState('windows-11');
  const [serviceVersion, setServiceVersion] = useState('9.7');
  const [xamppVersion, setXamppVersion] = useState('');
  const [scanMode, setScanMode] = useState('balanced');
  const [step, setStep] = useState(1);
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [detectError, setDetectError] = useState('');
  const [apacheLayout, setApacheLayout] = useState('auto');
  const [xamppRoot, setXamppRoot] = useState('C:/xampp');
  const [detectedSource, setDetectedSource] = useState('');
  const [scanError, setScanError] = useState('');
  const [activeFindingCode, setActiveFindingCode] = useState('');
  const [showOverallSuggestions, setShowOverallSuggestions] = useState(false);
  const [showFloatingNote, setShowFloatingNote] = useState(true);

  const filteredModules = useMemo(() => {
    return moduleCatalog.filter((item) => {
      const osOk = osFamily === 'all' || item.osFamily === osFamily;
      const serviceOk = service === 'all' || item.service === service;
      return osOk && serviceOk;
    });
  }, [osFamily, service]);

  const currentModule = useMemo(() => {
    if (selectedId) {
      const found = filteredModules.find((item) => item.id === selectedId);
      if (found) return found;
    }
    return filteredModules[0] || null;
  }, [filteredModules, selectedId]);

  const selectedFinding = useMemo(() => {
    if (!result) return null;
    return result.failedRows.find((row) => row.code === activeFindingCode) || null;
  }, [result, activeFindingCode]);

  useEffect(() => {
    let canceled = false;

    async function detectHost() {
      try {
        const response = await fetch('/api/detect/host');
        if (!response.ok) return;
        const payload = await response.json();
        if (canceled) return;
        if (payload.osFamily) setOsFamily(payload.osFamily);
        if (payload.osVersion) setOsVersion(payload.osVersion);
      } catch {
        // Endpoint might be unavailable outside desktop host.
      }
    }

    detectHost();
    return () => {
      canceled = true;
    };
  }, []);

  useEffect(() => {
    if (!currentModule || service === 'all') return;

    let canceled = false;
    async function detectServiceVersion() {
      const layoutQuery = currentModule.service.startsWith('apache-') ? `&layout=${encodeURIComponent(apacheLayout)}` : '';
      const xamppQuery = currentModule.service.startsWith('apache-') && apacheLayout === 'xampp'
        ? `&xamppRoot=${encodeURIComponent(xamppRoot)}`
        : '';
      try {
        const response = await fetch(`/api/detect/service?type=${encodeURIComponent(currentModule.service)}${layoutQuery}${xamppQuery}`);
        if (!response.ok) return;
        const payload = await response.json();
        if (canceled) return;
        if (payload.serviceVersion) {
          setServiceVersion(payload.serviceVersion);
        }
        if (payload.hits && payload.hits.length > 0) {
          setDetectedSource(`${payload.hits[0].source} | ${payload.hits[0].command}`);
        } else {
          setDetectedSource('');
        }
      } catch {
        // Keep manual input if detection endpoint is unavailable.
      }
    }

    detectServiceVersion();
    return () => {
      canceled = true;
    };
  }, [currentModule, service, apacheLayout, xamppRoot]);

  async function onDetectVersions() {
    setDetecting(true);
    setDetectError('');
    try {
      const hostRes = await fetch('/api/detect/host');
      if (!hostRes.ok) throw new Error('Cannot detect host version.');
      const host = await hostRes.json();
      if (host.osFamily) setOsFamily(host.osFamily);
      if (host.osVersion) setOsVersion(host.osVersion);

      if (currentModule && currentModule.service !== 'all') {
        const layoutQuery = currentModule.service.startsWith('apache-') ? `&layout=${encodeURIComponent(apacheLayout)}` : '';
        const xamppQuery = currentModule.service.startsWith('apache-') && apacheLayout === 'xampp'
          ? `&xamppRoot=${encodeURIComponent(xamppRoot)}`
          : '';
        const svcRes = await fetch(`/api/detect/service?type=${encodeURIComponent(currentModule.service)}${layoutQuery}${xamppQuery}`);
        if (svcRes.ok) {
          const svc = await svcRes.json();
          if (svc.serviceVersion) setServiceVersion(svc.serviceVersion);
          if (svc.hits && svc.hits.length > 0) {
            setDetectedSource(`${svc.hits[0].source} | ${svc.hits[0].command}`);
          }
        }
      }
    } catch {
      setDetectError('Cannot auto-detect in this runtime. Enter versions manually.');
    } finally {
      setDetecting(false);
    }
  }

  function onRun() {
    if (!currentModule) return;
    setRunning(true);
    setResult(null);
    setScanError('');
    setStep(4);

    const payload = {
      module_id: currentModule.id,
      os_version: osVersion,
      service_version: serviceVersion,
    };

    if (
      currentModule.service.startsWith('apache-') &&
      apacheLayout === 'xampp' &&
      xamppRoot
    ) {
      payload.xampp_root = xamppRoot;
    }

    if (currentModule.service.startsWith('apache-') && apacheLayout === 'xampp' && xamppVersion) {
      payload.xampp_version = xamppVersion;
    }

    fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then((response) => {
        if (!response.ok) {
          return response.json().then((err) => {
            throw new Error(err.error || `HTTP ${response.status}`);
          });
        }
        return response.json();
      })
      .then((backendReport) => {
        const transformed = transformBackendResult(backendReport);
        setResult(transformed);
        const firstFailed = transformed.failedRows[0];
        setActiveFindingCode(firstFailed ? firstFailed.code : '');
        setShowOverallSuggestions(false);
      })
      .catch((err) => {
        setScanError(`Scan failed: ${err.message}`);
        setResult(null);
      })
      .finally(() => {
        setRunning(false);
      });
  }

  function resetFlow() {
    setResult(null);
    setRunning(false);
    setStep(1);
    setActiveFindingCode('');
    setShowOverallSuggestions(false);
  }

  const tableColumns = [
    {
      title: 'Code',
      dataIndex: 'code',
      key: 'code',
      width: 180,
    },
    {
      title: 'Rule',
      dataIndex: 'title',
      key: 'title',
      width: 260,
    },
    {
      title: 'Where',
      dataIndex: 'where',
      key: 'where',
      ellipsis: true,
    },
    {
      title: 'Why',
      dataIndex: 'reason',
      key: 'reason',
      ellipsis: true,
    },
    {
      title: 'Status',
      key: 'status',
      width: 100,
      render: (_, row) => (row.passed ? <Tag color="success">PASS</Tag> : <Tag color="error">FAIL</Tag>),
    },
  ];

  const stepItems = stepLabels.map((label) => ({ title: label }));
  const drawerWidth = screens.lg ? 560 : screens.md ? 480 : '100%';

  return (
    <ConfigProvider
      theme={{
        algorithm: defaultAlgorithm,
        token: {
          colorPrimary: '#1677ff',
          colorInfo: '#1677ff',
          colorSuccess: '#52c41a',
          colorWarning: '#faad14',
          colorError: '#ff4d4f',
          colorBgBase: '#ffffff',
          colorBgLayout: '#f5f7fb',
          colorTextBase: '#1f2937',
          colorBorder: '#d9e2f2',
          borderRadius: 12,
          fontSize: 14,
        },
      }}
    >
      <Layout className="antd-shell">
        {showFloatingNote && (
          <div className="floating-note">
            <Alert
              message="Hint"
              description="Click a FAIL row to open detail. Missing directives (no line number) are moved to Overall Suggestions."
              type="info"
              showIcon
              closable
              onClose={() => setShowFloatingNote(false)}
            />
          </div>
        )}

        <Header className="antd-header">
          <div className="app-container">
            <Card className="panel-card">
              <Space direction="vertical" size={2}>
                <Text type="secondary">VulnMngSys React Console</Text>
                <Title level={3} style={{ margin: 0 }}>Hardening Scan Journey</Title>
                <Text type="secondary">Clean, responsive Ant Design interface for real config scanning.</Text>
              </Space>
            </Card>
          </div>
        </Header>

        <Content className="antd-content">
          <div className="app-container">
            <Space direction="vertical" size="large" style={{ width: '100%' }}>
              <Card className="panel-card" bodyStyle={{ paddingBottom: 12 }}>
                <Steps
                  current={step - 1}
                  items={stepItems}
                  responsive
                  onChange={(index) => setStep(index + 1)}
                />
              </Card>

              {step === 1 && (
                <Card className="panel-card" title="Step 1: Select Target Profile">
                  <Row gutter={[16, 16]}>
                    <Col xs={24} md={12}>
                      <Text>OS Family</Text>
                      <Select
                        value={osFamily}
                        onChange={setOsFamily}
                        style={{ width: '100%', marginTop: 6 }}
                        options={osOptions.map((opt) => ({ label: opt, value: opt }))}
                      />
                    </Col>
                    <Col xs={24} md={12}>
                      <Text>Service</Text>
                      <Select
                        value={service}
                        onChange={setService}
                        style={{ width: '100%', marginTop: 6 }}
                        options={serviceOptions.map((opt) => ({ label: opt, value: opt }))}
                      />
                    </Col>
                    <Col xs={24} md={12}>
                      <Text>OS Version</Text>
                      <Input value={osVersion} onChange={(e) => setOsVersion(e.target.value)} style={{ marginTop: 6 }} />
                    </Col>
                    <Col xs={24} md={12}>
                      <Text>Service Version</Text>
                      <Input value={serviceVersion} onChange={(e) => setServiceVersion(e.target.value)} style={{ marginTop: 6 }} />
                    </Col>

                    {(service === 'apache-http' || service === 'apache-tomcat') && (
                      <>
                        <Col xs={24} md={12}>
                          <Text>Apache Layout</Text>
                          <Select
                            value={apacheLayout}
                            onChange={setApacheLayout}
                            style={{ width: '100%', marginTop: 6 }}
                            options={apacheLayoutOptions.map((opt) => ({ label: opt, value: opt }))}
                          />
                        </Col>
                        {apacheLayout === 'xampp' && (
                          <>
                            <Col xs={24} md={12}>
                              <Text>XAMPP Root Path</Text>
                              <Input value={xamppRoot} onChange={(e) => setXamppRoot(e.target.value)} style={{ marginTop: 6 }} />
                            </Col>
                            <Col xs={24} md={12}>
                              <Text>XAMPP Version</Text>
                              <Input
                                value={xamppVersion}
                                onChange={(e) => setXamppVersion(e.target.value)}
                                placeholder="e.g. 8.1.25"
                                style={{ marginTop: 6 }}
                              />
                            </Col>
                          </>
                        )}
                      </>
                    )}

                    <Col xs={24}>
                      <Space wrap>
                        <Button onClick={onDetectVersions} loading={detecting}>Auto-detect Host + Service</Button>
                        {detectedSource && <Text type="secondary">Detected via: {detectedSource}</Text>}
                      </Space>
                      {detectError && <Alert style={{ marginTop: 12 }} type="warning" message={detectError} showIcon />}
                    </Col>
                  </Row>
                </Card>
              )}

              {step === 2 && (
                <Card className="panel-card" title="Step 2: Choose Module">
                  <Space direction="vertical" style={{ width: '100%' }} size="middle">
                    <div>
                      <Text>Module</Text>
                      <Select
                        style={{ width: '100%', marginTop: 6 }}
                        value={currentModule?.id || ''}
                        onChange={setSelectedId}
                        options={filteredModules.map((item) => ({ label: item.name, value: item.id }))}
                      />
                    </div>
                    <div>
                      <Text>Scan Mode</Text>
                      <div style={{ marginTop: 8 }}>
                        <Radio.Group value={scanMode} onChange={(e) => setScanMode(e.target.value)}>
                          <Radio.Button value="strict">Strict</Radio.Button>
                          <Radio.Button value="balanced">Balanced</Radio.Button>
                          <Radio.Button value="quick">Quick</Radio.Button>
                        </Radio.Group>
                      </div>
                    </div>
                  </Space>
                </Card>
              )}

              {step === 3 && (
                <Card className="panel-card" title="Step 3: Review and Confirm">
                  <Descriptions bordered column={screens.md ? 2 : 1} size="small">
                    <Descriptions.Item label="Target OS">{osFamily}</Descriptions.Item>
                    <Descriptions.Item label="OS Version">{osVersion || 'N/A'}</Descriptions.Item>
                    <Descriptions.Item label="Service">{service}</Descriptions.Item>
                    <Descriptions.Item label="Service Version">{serviceVersion || 'N/A'}</Descriptions.Item>
                    <Descriptions.Item label="XAMPP Version">{apacheLayout === 'xampp' ? (xamppVersion || 'N/A') : 'N/A'}</Descriptions.Item>
                    <Descriptions.Item label="Selected Module" span={screens.md ? 2 : 1}>
                      {currentModule ? currentModule.name : 'No module selected'}
                    </Descriptions.Item>
                    <Descriptions.Item label="Scan Mode" span={screens.md ? 2 : 1}>{scanMode}</Descriptions.Item>
                  </Descriptions>
                  <Space style={{ marginTop: 16 }}>
                    <Button onClick={() => setStep(2)}>Back</Button>
                    <Button type="primary" onClick={onRun} disabled={!currentModule} loading={running}>Run Scan</Button>
                  </Space>
                </Card>
              )}

              {step === 4 && (
                <Card className="panel-card" title="Step 4: Scan Result">
                  {!result && !running && !scanError && <Alert type="info" message="No scan result yet." showIcon />}
                  {scanError && <Alert type="error" message={scanError} showIcon />}
                  {running && (
                    <div style={{ textAlign: 'center', padding: 30 }}>
                      <Spin size="large" />
                      <Paragraph style={{ marginTop: 12 }}>Analyzing configuration and calculating score...</Paragraph>
                    </div>
                  )}

                  {result && (
                    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                      {result.warnings.length > 0 && (
                        <Card className="panel-card" title="Version upgrade recommendation">
                          <Space direction="vertical" style={{ width: '100%' }} size="small">
                            {result.warnings.map((warning) => (
                              <Alert key={warning} type="warning" showIcon message={warning} />
                            ))}
                          </Space>
                        </Card>
                      )}

                      {result.cveAdvisories.length > 0 && (
                        <Card className="panel-card" title="Detected CVE advisories">
                          <List
                            dataSource={result.cveAdvisories}
                            renderItem={(item) => (
                              <List.Item>
                                <List.Item.Meta
                                  title={<Space wrap><Text strong>{item.cveId}</Text><Tag color={item.severity === 'critical' ? 'red' : 'orange'}>{item.severity.toUpperCase()}</Tag><Tag color="blue">Khả năng: {item.likelihood}</Tag></Space>}
                                  description={(
                                    <Space direction="vertical" size={0}>
                                      <Text>{item.title}</Text>
                                      <Text type="secondary">{item.reason}</Text>
                                      <Text type="secondary">Reference: {item.reference}</Text>
                                    </Space>
                                  )}
                                />
                              </List.Item>
                            )}
                          />
                        </Card>
                      )}

                      <Row gutter={[16, 16]}>
                        <Col xs={24} md={8}><Card className="stat-card"><Statistic title="Hardening Index" value={result.hardeningIndex} suffix="/100" /></Card></Col>
                        <Col xs={24} md={8}><Card className="stat-card"><Statistic title="Grade" value={result.grade} /></Card></Col>
                        <Col xs={24} md={8}><Card className="stat-card"><Statistic title="Pass Ratio" value={`${result.passedChecks}/${result.totalChecks}`} /></Card></Col>
                      </Row>

                      <Space wrap>
                        <Button onClick={() => setShowOverallSuggestions((prev) => !prev)}>
                          {showOverallSuggestions
                            ? 'Hide Overall Suggestions'
                            : `Show Overall Suggestions (${result.overallSuggestions.length})`}
                        </Button>
                        <Button onClick={resetFlow}>Reset</Button>
                      </Space>

                      {showOverallSuggestions && result.overallSuggestions.length > 0 && (
                        <Card className="panel-card" title="Missing directives to add">
                          <List
                            dataSource={result.overallSuggestions}
                            renderItem={(item) => (
                              <List.Item>
                                <List.Item.Meta
                                  title={`${item.code} - ${item.title}`}
                                  description={<Text code>{item.suggestedLine}</Text>}
                                />
                              </List.Item>
                            )}
                          />
                        </Card>
                      )}

                      <Card className="panel-card" title="Detected mismatches with line number (click FAIL row for details)">
                        <Table
                          dataSource={result.failedRows}
                          columns={tableColumns}
                          pagination={{ pageSize: screens.md ? 8 : 5 }}
                          scroll={{ x: 980 }}
                          size={screens.md ? 'middle' : 'small'}
                          onRow={(row) => ({
                            onClick: () => setActiveFindingCode(row.code),
                          })}
                        />
                      </Card>
                    </Space>
                  )}
                </Card>
              )}

              <Card className="panel-card">
                <Space wrap>
                  <Button onClick={resetFlow}>Reset</Button>
                  <Button onClick={() => setStep((prev) => Math.max(prev - 1, 1))} disabled={step === 1}>Back</Button>
                  {step < 3 && <Button type="primary" onClick={() => setStep((prev) => Math.min(prev + 1, 4))}>Next</Button>}
                </Space>
              </Card>
            </Space>
          </div>
        </Content>

        <Drawer
          title={selectedFinding ? `${selectedFinding.code} - ${selectedFinding.title}` : 'Finding details'}
          placement="right"
          width={drawerWidth}
          open={Boolean(selectedFinding)}
          onClose={() => setActiveFindingCode('')}
        >
          {selectedFinding && (
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <Descriptions bordered size="small" column={1}>
                <Descriptions.Item label="Where it failed">{selectedFinding.where}</Descriptions.Item>
                <Descriptions.Item label="Observed value">{selectedFinding.observed}</Descriptions.Item>
                {selectedFinding.actualLine && (
                  <Descriptions.Item label="Actual line in conf">
                    <Text code>{selectedFinding.actualLine}</Text>
                  </Descriptions.Item>
                )}
                <Descriptions.Item label="Line to fix">
                  <Text code>{selectedFinding.suggestedLine || '(see full baseline below)'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Why this config matters">
                  <Paragraph style={{ marginBottom: 0 }}>
                    {selectedFinding.explanation || 'No additional explanation available for this rule.'}
                  </Paragraph>
                </Descriptions.Item>
                <Descriptions.Item label="Baseline from sample file">
                  <Text>{selectedFinding.expected}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="Why not pass">{selectedFinding.whyFail}</Descriptions.Item>
                <Descriptions.Item label="Reference">{selectedFinding.cisRef}</Descriptions.Item>
              </Descriptions>

              {selectedFinding.fixCommands.length > 0 && (
                <Card size="small" title="Suggested fix commands">
                  {selectedFinding.fixCommands.map((cmd) => (
                    <Paragraph key={cmd} copyable={{ text: cmd }} style={{ marginBottom: 8 }}>
                      <Text code>{cmd}</Text>
                    </Paragraph>
                  ))}
                </Card>
              )}
            </Space>
          )}
        </Drawer>
      </Layout>
    </ConfigProvider>
  );
}
