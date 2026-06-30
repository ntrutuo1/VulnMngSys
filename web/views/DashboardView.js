function DonutChart({ segments, size = 118 }) {
  const total = segments.reduce((s, x) => s + (x.value || 0), 0);
  const r     = (size - 22) / 2;
  const cx    = size / 2, cy = size / 2;
  const circ  = 2 * Math.PI * r;
  let cumDash = 0;

  return (
    <svg width={size} height={size} style={{ display: 'block' }}>
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#182034" strokeWidth="12" />
      {/* Segments */}
      {total > 0 && segments.filter(s => s.value > 0).map((seg, i) => {
        const dash = (seg.value / total) * circ;
        const el = (
          <circle key={i} cx={cx} cy={cy} r={r}
            fill="none" stroke={seg.color} strokeWidth="12"
            strokeDasharray={`${dash} ${circ - dash}`}
            strokeDashoffset={circ * 0.25 - cumDash}
            strokeLinecap="butt"
            style={{ transition: 'stroke-dasharray .5s ease' }}
          />
        );
        cumDash += dash;
        return el;
      })}
      {/* Center text */}
      <text x={cx} y={cy + 6} textAnchor="middle"
        fill={C.txt1} fontSize="15" fontWeight="700" fontFamily="Inter">
        {total}
      </text>
    </svg>
  );
}

function DashboardPage({ refreshKey, onOpen }) {
  const [stats,  setStats]  = useState({ totals: [], risk: [] });
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    api('/api/stats/dashboard').then(setStats).catch(() => {});
    api('/api/scans?limit=8').then(setRecent).catch(() => {});
  }, [refreshKey]);

  const total     = stats.totals.reduce((s, t) => s + t.count, 0);
  const completed = (stats.totals.find(t => t.status === 'COMPLETED') || {}).count || 0;
  const running   = (stats.totals.find(t => t.status === 'RUNNING') || {}).count || 0;
  const highRisk  = stats.risk.filter(r => ['critical', 'high'].includes(r.severity)).reduce((s, r) => s + r.count, 0);

  const metrics = [
    { label: 'Total Scans',     val: total,     sub: `${running} active`,  accent: C.accent  },
    { label: 'Completed',       val: completed, sub: 'successfully',        accent: C.green   },
    { label: 'High Risk',       val: highRisk,  sub: 'critical + high',    accent: C.critical },
    { label: 'Severity Levels', val: stats.risk.filter(r => r.count > 0).length, sub: 'in database', accent: C.medium },
  ];

  const riskSegs = [
    { label: 'Critical', color: C.critical, value: (stats.risk.find(r => r.severity === 'critical') || {}).count || 0 },
    { label: 'High',     color: C.high,     value: (stats.risk.find(r => r.severity === 'high') || {}).count || 0 },
    { label: 'Medium',   color: C.medium,   value: (stats.risk.find(r => r.severity === 'medium') || {}).count || 0 },
    { label: 'Low',      color: C.low,      value: (stats.risk.find(r => r.severity === 'low') || {}).count || 0 },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Metric cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
        {metrics.map((m, i) => (
          <div key={i} className="fade-in" style={{
            background: C.bgSurface, border: `1px solid ${C.border}`,
            borderRadius: 10, padding: '16px 18px', position: 'relative', overflow: 'hidden',
            animationDelay: `${i * .06}s`,
          }}>
            {/* Accent line */}
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: m.accent, borderRadius: '10px 10px 0 0' }} />
            {/* Glow orb */}
            <div style={{ position: 'absolute', top: -24, right: -18, width: 72, height: 72, borderRadius: '50%', background: m.accent, opacity: .06, filter: 'blur(20px)' }} />
            <div style={{ fontSize: 10, fontWeight: 600, color: C.txt3, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 9 }}>{m.label}</div>
            <div style={{ fontSize: 32, fontWeight: 700, color: C.txt1, lineHeight: 1, fontVariantNumeric: 'tabular-nums', marginBottom: 5 }}>{m.val}</div>
            <div style={{ fontSize: 11, color: C.txt2 }}>{m.sub}</div>
          </div>
        ))}
      </div>

      {/* Content grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 290px', gap: 14 }}>
        {/* Recent scans */}
        <Panel title="Recent Scans" icon={<Ico.Clock />} bodyPad="0">
          {recent.length === 0 ? (
            <div style={{ padding: '40px 0', textAlign: 'center', color: C.txt3, fontSize: 13 }}>
              No scans yet — start a scan to populate the dashboard.
            </div>
          ) : (
            <div>
              {recent.map((scan, i) => {
                const dur = scan.completed_at
                  ? `${Math.round((new Date(scan.completed_at) - new Date(scan.created_at)) / 1000)}s`
                  : null;
                return (
                  <div key={scan.id}
                    className="clickable-row fade-in"
                    onClick={() => onOpen(scan.id)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 12, padding: '11px 16px',
                      borderBottom: i < recent.length - 1 ? `1px solid ${C.border}` : 'none',
                      animationDelay: `${i * .04}s`,
                    }}>
                    {/* Icon */}
                    <div style={{
                      width: 32, height: 32, borderRadius: 7, flexShrink: 0,
                      background: scan.type === 'cis' ? 'rgba(124,92,252,.12)' : 'rgba(79,131,255,.12)',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      color: scan.type === 'cis' ? C.purple : C.accent,
                    }}>
                      {scan.type === 'cis' ? <Ico.CheckList /> : <Ico.Radar />}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                        <ScanTypeBadge type={scan.type} />
                        <span style={{ fontSize: 12.5, color: C.txt1, fontFamily: C.txtMono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {scan.target}
                        </span>
                      </div>
                      <div style={{ fontSize: 11, color: C.txt3, fontFamily: C.txtMono }}>
                        {dayjs(scan.created_at).format('YYYY-MM-DD HH:mm')}
                        {dur && <span style={{ marginLeft: 8, color: C.txt3 }}>· {dur}</span>}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      {scan.status === 'COMPLETED' && (
                        <span style={{
                          fontSize: 14, fontWeight: 700, fontFamily: C.txtMono,
                          color: (scan.score || 0) >= 55 ? C.high : C.green,
                        }}>{Math.round(scan.score || 0)}</span>
                      )}
                      <StatusBadge status={scan.status} />
                      <Ico.Arrow />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Panel>

        {/* Risk distribution */}
        <Panel title="Risk Distribution" icon={<Ico.Warning />}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 18 }}>
            <DonutChart segments={riskSegs} size={118} />
            <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 9 }}>
              {riskSegs.map(seg => (
                <div key={seg.label} style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: seg.color, flexShrink: 0, boxShadow: `0 0 6px ${seg.color}55` }} />
                  <span style={{ fontSize: 12, color: C.txt2, flex: 1 }}>{seg.label}</span>
                  <span style={{ fontSize: 13, fontWeight: 700, color: C.txt1, fontFamily: C.txtMono }}>{seg.value}</span>
                </div>
              ))}
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}
