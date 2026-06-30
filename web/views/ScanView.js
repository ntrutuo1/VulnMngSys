function ScanPage({ type, onChanged, onOpen }) {
  const [scanId,     setScanId]     = useState(null);
  const [loading,    setLoading]    = useState(false);
  const [benchmarks, setBenchmarks] = useState([]);
  const [form]       = Form.useForm();
  const detail  = usePoll(scanId, onChanged);
  const isRun   = detail?.job?.status === 'RUNNING';
  const isDone  = detail?.scan?.status === 'COMPLETED' || detail?.scan?.status === 'FAILED';

  useEffect(() => {
    if (type === 'cis') api('/api/cis/benchmarks').then(setBenchmarks).catch(() => {});
    
    // Fetch LAN IP for target default value
    api('/api/status').then(res => {
      if (res.lan_ip) {
        form.setFieldsValue({ target: res.lan_ip });
      }
    }).catch(() => {});
  }, [type, form]);

  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    (detail?.findings || []).forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });
    return c;
  }, [detail]);

  const start = async values => {
    setLoading(true);
    try {
      const path = type === 'cis' ? '/api/scans/cis' : '/api/scans/services';
      const res  = await api(path, { method: 'POST', body: JSON.stringify(values) });
      setScanId(res.scanId);
      message.success('Scan started successfully');
    } catch (e) {
      message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  const isCis  = type === 'cis';
  const Icon   = isCis ? Ico.CheckList : Ico.Radar;
  const label  = isCis ? 'CIS Benchmark Audit' : 'Service & CVE Scan';

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 14, alignItems: 'start' }}>

      {/* ── LEFT: Config ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <Panel title={label} icon={<Icon />}>
          <Form form={form} layout="vertical" onFinish={start} initialValues={{ target: '127.0.0.1' }}>
            <Form.Item label="Target Host" name="target"
              rules={[{ required: true, message: 'Please enter a target' }]}
              style={{ marginBottom: 12 }}>
              <Input
                placeholder="IP address"
                maxLength={120}
                style={{ fontFamily: C.txtMono, fontSize: 12 }}
                prefix={<span style={{ color: C.txt3, fontSize: 11 }}>@</span>}
              />
            </Form.Item>

            {isCis && (
              <Form.Item label="Benchmark" name="benchmark" style={{ marginBottom: 12 }}
                tooltip="Leave blank to auto-detect from the running OS version">
                <Select allowClear placeholder="Auto-detect from OS version" style={{ fontSize: 12 }}>
                   {benchmarks.map(b => (
                    <Select.Option key={b.benchmark} value={b.benchmark}>
                      <span style={{ fontFamily: C.txtMono, fontSize: 11 }}>{b.benchmark}</span>
                      <span style={{ color: C.txt3, fontSize: 10, marginLeft: 6 }}>({b.count} rules)</span>
                    </Select.Option>
                  ))}
                </Select>
              </Form.Item>
            )}

            {!isCis && (
              <Collapse ghost style={{ marginTop: -4, marginBottom: 12 }} items={[{
                key: 'adv',
                label: <span style={{ fontSize: 11, fontWeight: 600, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.5px' }}>Advanced Settings</span>,
                children: (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <Form.Item label="Metasploit Username" name="username" style={{ marginBottom: 0 }}>
                      <Input placeholder="Current User / Administrator" style={{ fontSize: 12 }} />
                    </Form.Item>
                    <Form.Item label="Metasploit Password" name="password" style={{ marginBottom: 0 }}>
                      <Input.Password placeholder="Password123" style={{ fontSize: 12 }} />
                    </Form.Item>
                    <Form.Item label="Attacker LPORT" name="lport" style={{ marginBottom: 0 }}>
                      <InputNumber placeholder="4444" style={{ width: '100%', fontSize: 12 }} />
                    </Form.Item>
                  </div>
                )
              }]} />
            )}



            <Button type="primary" htmlType="submit" loading={loading}
              disabled={isRun} block size="middle" style={{ marginBottom: 10 }}>
              {isRun ? '⟳ Scanning…' : '▶ Start Scan'}
            </Button>
          </Form>

          {/* Info note */}
          <div style={{
            marginTop: 4, padding: '9px 11px',
            background: 'rgba(79,131,255,.05)', borderRadius: 7,
            border: '1px solid rgba(79,131,255,.12)',
          }}>
            <div style={{ fontSize: 11, color: C.txt2, lineHeight: 1.6 }}>
              {isCis
                ? '📋 Audits Windows security configuration against CIS benchmarks. Benchmark is auto-detected from OS version if not specified.'
                : '🔍 Enumerates running services, listening ports, installed software, and matches findings against the CVE database.'}
            </div>
          </div>
        </Panel>

        {/* Severity summary (shown after scan) */}
        {isDone && (
          <Panel title="Finding Summary" bodyPad="12px 14px">
            {Object.entries(sevCounts).map(([sev, cnt]) => {
              const max = Math.max(...Object.values(sevCounts), 1);
              return (
                <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 9 }}>
                  <div style={{ width: 64 }}><SevTag severity={sev} /></div>
                  <div style={{ flex: 1, height: 4, borderRadius: 2, background: '#182034', overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', borderRadius: 2,
                      width: `${(cnt / max) * 100}%`,
                      background: (SEV[sev] || {}).color,
                      transition: 'width .5s ease',
                    }} />
                  </div>
                  <span style={{ fontSize: 13, fontWeight: 700, color: C.txt1, fontFamily: C.txtMono, minWidth: 18, textAlign: 'right' }}>{cnt}</span>
                </div>
              );
            })}
          </Panel>
        )}
      </div>

      {/* ── RIGHT: Live results ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {/* Progress */}
        {detail?.job && <ScanProgressWidget job={detail.job} />}

        {/* Results panel */}
        {detail?.scan ? (
          <Panel
            title={`Results — ${(detail.findings || []).length} findings`}
            icon={<Ico.Doc />}
            extra={isDone && (
              <Button size="small" onClick={() => onOpen(detail.scan.id)}
                style={{ fontSize: 11 }}>Full Report →</Button>
            )}
          >
            {/* Scan meta bar */}
            <div style={{
              display: 'flex', gap: 18, flexWrap: 'wrap',
              padding: '10px 12px', background: C.bgCard,
              borderRadius: 8, marginBottom: 14, alignItems: 'center',
            }}>
              {[
                ['Target',  <span style={{ fontFamily: C.txtMono, fontSize: 12 }}>{detail.scan.target}</span>],
                ['Status',  <StatusBadge status={detail.scan.status} />],
                ['Ratio',   (() => {
                   const s = detail.scan.summary || {};
                   let pct = 1.0;
                   if (detail.scan.type === 'cis' && s.rules > 0) {
                     pct = (s.passed || 0) / s.rules;
                   } else if (detail.scan.type === 'services') {
                     const total_det = s.detectedServices?.length || 0;
                     const affected = s.modulesUsed?.length || 0;
                     const clean = total_det > 0 ? Math.max(0, total_det - affected) : 1;
                     pct = total_det > 0 ? (clean / total_det) : 1.0;
                   }
                   const color = pct >= 0.9 ? C.green : pct >= 0.7 ? C.medium : pct >= 0.4 ? C.high : C.critical;
                   return <span style={{ fontFamily: C.txtMono, fontWeight: 700, fontSize: 14, color }}>{Math.round(pct * 100)}%</span>;
                 })()],
                ['Started', <span style={{ fontFamily: C.txtMono, fontSize: 11, color: C.txt2 }}>{dayjs(detail.scan.created_at).format('HH:mm:ss')}</span>],
              ].map(([lbl, val]) => (
                <div key={lbl}>
                  <div style={{ fontSize: 9.5, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 2 }}>{lbl}</div>
                  <div>{val}</div>
                </div>
              ))}
            </div>

            <FindingsList findings={detail.findings} />
          </Panel>
        ) : (
          /* Empty state */
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center',
            justifyContent: 'center', padding: '80px 24px',
            background: C.bgSurface, border: `1px solid ${C.border}`,
            borderRadius: 10, color: C.txt3, gap: 14,
          }}>
            <div style={{ position: 'relative' }}>
              <div style={{ width: 52, height: 52, borderRadius: '50%', background: 'rgba(79,131,255,.06)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon s={28} />
              </div>
              {loading && <div className="scan-ping-wrap" style={{ position: 'absolute', inset: 0, borderRadius: '50%' }} />}
            </div>
            <div style={{ fontSize: 13, textAlign: 'center' }}>Configure a target and click <strong style={{ color: C.txt2 }}>Start Scan</strong></div>
          </div>
        )}
      </div>
    </div>
  );
}
