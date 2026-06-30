const { useEffect, useMemo, useState } = React;
const { Alert, Button, Card, Col, ConfigProvider, Descriptions, Form, Input, Layout, Menu, Progress, Row, Space, Statistic, Table, Tabs, Tag, Typography, message } = antd;
const { Header, Sider, Content } = Layout;
const api = (path, options) => fetch(path, { headers: { "Content-Type": "application/json" }, ...options }).then(async r => {
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || "Request failed");
  return data;
});

function severityColor(s) {
  return { critical: "red", high: "volcano", medium: "orange", low: "blue" }[s] || "default";
}

function usePoll(scanId, onDone) {
  const [detail, setDetail] = useState(null);
  useEffect(() => {
    if (!scanId) return;
    const tick = () => api(`/api/scans/${scanId}`).then(d => {
      setDetail(d);
      const status = d.job?.status || d.scan?.status;
      if (status === "COMPLETED" || status === "FAILED") onDone?.();
    }).catch(e => message.error(e.message));
    tick();
    const id = setInterval(tick, 1500);
    return () => clearInterval(id);
  }, [scanId]);
  return detail;
}

function Dashboard({ refreshKey }) {
  const [stats, setStats] = useState({ totals: [], risk: [] });
  useEffect(() => { api("/api/stats/dashboard").then(setStats); }, [refreshKey]);
  const total = stats.totals.reduce((n, x) => n + x.count, 0);
  const high = stats.risk.filter(x => ["critical", "high"].includes(x.severity)).reduce((n, x) => n + x.count, 0);
  return <Row gutter={[12, 12]}>
    <Col xs={24} md={8}><Card className="metric"><Statistic title="Lượt quét" value={total} /></Card></Col>
    <Col xs={24} md={8}><Card className="metric"><Statistic title="Rủi ro cao" value={high} valueStyle={{ color: high ? "#cf1322" : "#3f8600" }} /></Card></Col>
    <Col xs={24} md={8}><Card className="metric"><Statistic title="SQLite" value="Local" /></Card></Col>
    <Col span={24}><Card title="Phân bố rủi ro"><Space wrap>{stats.risk.map(x => <Tag key={x.severity} color={severityColor(x.severity)}>{x.severity}: {x.count}</Tag>)}</Space></Card></Col>
  </Row>;
}

function ScanPanel({ type, onChanged }) {
  const [scanId, setScanId] = useState(null);
  const [loading, setLoading] = useState(false);
  const detail = usePoll(scanId, onChanged);
  const start = async values => {
    setLoading(true);
    try {
      const path = type === "cis" ? "/api/scans/cis" : "/api/scans/services";
      const res = await api(path, { method: "POST", body: JSON.stringify(values) });
      setScanId(res.scanId);
      message.success("Đã bắt đầu quét");
    } catch (e) { message.error(e.message); }
    finally { setLoading(false); }
  };
  const title = type === "cis" ? "Quét cấu hình CIS" : "Quét dịch vụ và phần mềm";
  return <Row gutter={[12, 12]}>
    <Col xs={24} lg={8}>
      <Card title={title}>
        <Form layout="vertical" onFinish={start} initialValues={{ target: "localhost" }}>
          <Form.Item label="Mục tiêu" name="target" rules={[{ required: true }]}>
            <Input placeholder="localhost hoặc IP" maxLength={120} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={loading} block>Bắt đầu quét</Button>
        </Form>
        <Alert style={{ marginTop: 12 }} type="info" showIcon message="MVP quét local Windows bằng PowerShell cố định, không truyền input vào shell." />
      </Card>
    </Col>
    <Col xs={24} lg={16}>
      <Card title="Tiến trình" className="stage-wrap">
        <Progress percent={detail?.job?.percent || 0} status={detail?.job?.status === "FAILED" ? "exception" : "active"} />
        <Typography.Text>{detail?.job?.stage || "Chưa chạy"}</Typography.Text>
      </Card>
      <Card title="Kết quả" style={{ marginTop: 12 }} className="findings">
        <Findings detail={detail} />
      </Card>
    </Col>
  </Row>;
}

function Findings({ detail }) {
  if (!detail?.scan) return <Typography.Text type="secondary">Chưa có dữ liệu.</Typography.Text>;
  return <Table size="small" rowKey={(r, i) => `${r.title}-${i}`} pagination={{ pageSize: 6 }} dataSource={detail.findings} columns={[
    { title: "Mức", dataIndex: "severity", width: 90, render: v => <Tag color={severityColor(v)}>{v}</Tag> },
    { title: "Phát hiện", dataIndex: "title", width: 220 },
    { title: "Bằng chứng", dataIndex: "evidence", ellipsis: true },
    { title: "Khắc phục", dataIndex: "fix", ellipsis: true },
  ]} />;
}

function SystemInfo() {
  const [info, setInfo] = useState(null);
  return <Card title="Thu thập thông tin hệ thống" extra={<Button onClick={() => api("/api/system/info").then(setInfo).catch(e => message.error(e.message))}>Thu thập</Button>}>
    {info ? <Descriptions bordered size="small" column={1} items={Object.entries(info).map(([key, value]) => ({ key, label: key, children: String(value) }))} /> : <Typography.Text type="secondary">Bấm Thu thập để xem OS, hostname và kiến trúc.</Typography.Text>}
  </Card>;
}

function History({ refreshKey, onOpen }) {
  const [data, setData] = useState([]);
  const load = () => api("/api/scans?limit=50").then(setData);
  useEffect(() => { load(); }, [refreshKey]);
  const del = id => api(`/api/scans/${id}`, { method: "DELETE" }).then(load);
  return <Table rowKey="id" size="small" dataSource={data} pagination={{ pageSize: 10 }} columns={[
    { title: "Loại", dataIndex: "type", width: 110 },
    { title: "Mục tiêu", dataIndex: "target", width: 140 },
    { title: "Trạng thái", dataIndex: "status", width: 120, render: v => <Tag color={v === "COMPLETED" ? "green" : v === "FAILED" ? "red" : "blue"}>{v}</Tag> },
    { title: "Điểm", dataIndex: "score", width: 80 },
    { title: "Thời gian", dataIndex: "created_at", width: 190, render: v => dayjs(v).format("YYYY-MM-DD HH:mm") },
    { title: "", width: 150, render: (_, r) => <Space><Button size="small" onClick={() => onOpen(r.id)}>Xem</Button><Button danger size="small" onClick={() => del(r.id)}>Xóa</Button></Space> },
  ]} />;
}

function App() {
  const [tab, setTab] = useState("dashboard");
  const [refreshKey, setRefreshKey] = useState(0);
  const [selectedScan, setSelectedScan] = useState(null);
  const selectedDetail = usePoll(selectedScan);
  const bump = () => setRefreshKey(x => x + 1);
  const items = useMemo(() => [
    { key: "dashboard", label: "Tổng quan" },
    { key: "system", label: "Hệ thống" },
    { key: "services", label: "Quét dịch vụ" },
    { key: "cis", label: "CIS" },
    { key: "history", label: "Lịch sử" },
    { key: "report", label: "Báo cáo" },
  ], []);
  return <ConfigProvider theme={{ token: { borderRadius: 6, colorPrimary: "#1677ff" } }}>
    <Layout className="app-shell">
      <Sider breakpoint="lg" collapsedWidth="72">
        <div className="brand">VulnMngSys</div>
        <Menu theme="dark" mode="inline" selectedKeys={[tab]} items={items} onClick={e => setTab(e.key)} />
      </Sider>
      <Layout>
        <Header style={{ background: "#fff", padding: "0 18px" }}><Typography.Title level={4} style={{ margin: 0 }}>Windows Server Vulnerability MVP</Typography.Title></Header>
        <Content className="content">
          {tab === "dashboard" && <Dashboard refreshKey={refreshKey} />}
          {tab === "system" && <SystemInfo />}
          {tab === "services" && <ScanPanel type="services" onChanged={bump} />}
          {tab === "cis" && <ScanPanel type="cis" onChanged={bump} />}
          {tab === "history" && <History refreshKey={refreshKey} onOpen={id => { setSelectedScan(id); setTab("report"); }} />}
          {tab === "report" && <Card title="Báo cáo kết quả"><Findings detail={selectedDetail} /></Card>}
        </Content>
      </Layout>
    </Layout>
  </ConfigProvider>;
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
