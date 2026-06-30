function HistoryPage({ refreshKey, onOpen }) {
  const [data,         setData]         = useState([]);
  const [filterType,   setFilterType]   = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  const load = () => api('/api/scans?limit=200').then(setData).catch(() => {});
  useEffect(() => { load(); }, [refreshKey]);

  const remove = async id => {
    try {
      await api(`/api/scans/${id}`, { method: 'DELETE' });
      load();
      message.success('Scan deleted');
    } catch (e) {
      message.error(e.message);
    }
  };

  const filtered = useMemo(() => data.filter(s =>
    (filterType   === 'all' || s.type   === filterType) &&
    (filterStatus === 'all' || s.status === filterStatus)
  ), [data, filterType, filterStatus]);

  // ── Filter pill button ──
  const Pill = ({ active, onClick, children }) => (
    <button onClick={onClick} style={{
      background: active ? 'rgba(79,131,255,.15)' : C.bgCard,
      border: `1px solid ${active ? C.accent : C.border}`,
      color: active ? C.accent : C.txt2,
      borderRadius: 6, padding: '4px 13px', fontSize: 12,
      fontWeight: 600, cursor: 'pointer', fontFamily: 'Inter',
    }}>{children}</button>
  );

  const columns = [
    {
      title: 'Type', width: 100,
      render: (_, r) => <ScanTypeBadge type={r.type} />,
    },
    {
      title: 'Target', width: 170,
      render: (_, r) => <span style={{ fontFamily: C.txtMono, fontSize: 12, color: C.txt1 }}>{r.target}</span>,
    },
    {
      title: 'Status', width: 120,
      render: (_, r) => <StatusBadge status={r.status} />,
    },
    {
      title: 'Ratio', width: 72, align: 'center',
      render: (_, r) => {
        const s = r.summary || {};
        let pct = 1.0;
        if (r.type === 'cis' && s.rules > 0) {
          pct = (s.passed || 0) / s.rules;
        } else if (r.type === 'services') {
          const total_det = s.detectedServices?.length || 0;
          const affected = s.modulesUsed?.length || 0;
          const clean = total_det > 0 ? Math.max(0, total_det - affected) : 1;
          pct = total_det > 0 ? (clean / total_det) : 1.0;
        }
        const val = Math.round(pct * 100);
        const color = pct >= 0.9 ? C.green : pct >= 0.7 ? C.medium : pct >= 0.4 ? C.high : C.critical;
        return (
          <span style={{ fontFamily: C.txtMono, fontWeight: 700, fontSize: 12, color }}>
            {val}%
          </span>
        );
      },
    },
    {
      title: 'Started', width: 155,
      render: (_, r) => (
        <span style={{ fontFamily: C.txtMono, fontSize: 11, color: C.txt2 }}>
          {dayjs(r.created_at).format('YYYY-MM-DD HH:mm')}
        </span>
      ),
    },
    {
      title: 'Summary',
      render: (_, r) => {
        const s = r.summary;
        if (!s || typeof s !== 'object') return null;
        if (r.type === 'cis') return (
          <span style={{ fontSize: 11, color: C.txt2 }}>
            <span style={{ color: C.green }}>{s.passed ?? 0}</span> pass ·&nbsp;
            <span style={{ color: C.red }}>{s.failed ?? 0}</span> fail ·&nbsp;
            <span style={{ color: C.txt3 }}>{s.skipped ?? 0}</span> skip
            {s.benchmark && <span style={{ color: C.txt3 }}>&nbsp;· {s.benchmark}</span>}
          </span>
        );
        return (
          <span style={{ fontSize: 11, color: C.txt2 }}>
            {s.services ?? 0} svc · {(s.listeningPorts || []).length} ports · {s.software ?? 0} apps
            {s.detectedServices?.length > 0 && <span style={{ color: C.txt3 }}>&nbsp;· {s.detectedServices.join(', ')}</span>}
          </span>
        );
      },
    },
    {
      title: '', width: 140,
      render: (_, r) => (
        <div style={{ display: 'flex', gap: 6 }}>
          <Button size="small" onClick={() => onOpen(r.id)} style={{ fontSize: 11 }}>Report</Button>
          <Button size="small" danger onClick={() => remove(r.id)} style={{ fontSize: 11 }}>Delete</Button>
        </div>
      ),
    },
  ];

  return (
    <div>
      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ fontSize: 11, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.7px' }}>Type:</span>
        {[['all', 'All'], ['services', 'Services'], ['cis', 'CIS']].map(([v, l]) => (
          <Pill key={v} active={filterType === v} onClick={() => setFilterType(v)}>{l}</Pill>
        ))}
        <div style={{ width: 1, height: 18, background: C.border, margin: '0 4px' }} />
        <span style={{ fontSize: 11, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.7px' }}>Status:</span>
        {[['all', 'All'], ['COMPLETED', 'Completed'], ['RUNNING', 'Running'], ['FAILED', 'Failed']].map(([v, l]) => (
          <Pill key={v} active={filterStatus === v} onClick={() => setFilterStatus(v)}>{l}</Pill>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: C.txt3 }}>{filtered.length} result{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Table */}
      <div style={{ background: C.bgSurface, border: `1px solid ${C.border}`, borderRadius: 10, overflow: 'hidden' }}>
        <Table
          rowKey="id" size="small"
          dataSource={filtered} columns={columns}
          pagination={{ pageSize: 12, size: 'small', showSizeChanger: false }}
          locale={{ emptyText: (
            <div style={{ padding: '36px 0', color: C.txt3, textAlign: 'center' }}>No scans found</div>
          )}}
          onRow={row => ({ onClick: () => {} })}
        />
      </div>
    </div>
  );
}
