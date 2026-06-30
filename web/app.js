/* eslint-disable */
const { useEffect, useMemo, useState, useCallback, useRef } = React;
const {
  Alert, Button, ConfigProvider, Empty, Form, Input,
  Progress, Select, Space, Table, Tooltip, Typography, message,
  InputNumber, Collapse,
} = antd;
const { theme: antdTheme } = antd;

// ════════════════════════════════════════════════════════════
// API
// ════════════════════════════════════════════════════════════
const api = (path, opts) =>
  fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts }).then(async r => {
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || 'Request failed');
    return data;
  });
const DEFAULT_TARGET = window.location.hostname && window.location.hostname !== 'localhost'
  ? window.location.hostname
  : '127.0.0.1';

// ════════════════════════════════════════════════════════════
// DESIGN TOKENS
// ════════════════════════════════════════════════════════════
const C = {
  bgBase:    '#080d1a',
  bgSurface: '#0d1526',
  bgRaised:  '#111a30',
  bgCard:    '#141f35',
  bgInput:   '#182034',
  border:    'rgba(100,130,255,0.11)',
  borderHov: 'rgba(100,130,255,0.25)',

  accent:    '#4f83ff',
  accentEnd: '#7c5cfc',
  accentGlow:'rgba(79,131,255,0.28)',
  gradient:  'linear-gradient(135deg,#4f83ff 0%,#7c5cfc 100%)',

  txt1: '#dce8ff',
  txt2: '#7d8eb0',
  txt3: '#3a4a6a',
  txtMono: "'JetBrains Mono',monospace",

  critical: '#ff2d6d', critBg: 'rgba(255,45,109,0.11)',
  high:     '#ff7340', highBg: 'rgba(255,115,64,0.11)',
  medium:   '#f5c518', medBg:  'rgba(245,197,24,0.11)',
  low:      '#22d3ee', lowBg:  'rgba(34,211,238,0.11)',

  green:  '#10b981',
  red:    '#ff2d6d',
  blue:   '#4f83ff',
  purple: '#7c5cfc',
};

const SEV = {
  critical: { color: C.critical, bg: C.critBg },
  high:     { color: C.high,     bg: C.highBg },
  medium:   { color: C.medium,   bg: C.medBg  },
  low:      { color: C.low,      bg: C.lowBg  },
};

const STATUS = {
  COMPLETED: { color: C.green,  bg: 'rgba(16,185,129,0.11)' },
  RUNNING:   { color: C.blue,   bg: 'rgba(79,131,255,0.11)' },
  FAILED:    { color: C.red,    bg: 'rgba(255,45,109,0.11)' },
};

// ════════════════════════════════════════════════════════════
// SVG ICONS
// ════════════════════════════════════════════════════════════
const Ico = {
  Dashboard: ({ s=16 }) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1.5" fill="currentColor" opacity=".55"/>
      <rect x="9"   y="1.5" width="5.5" height="5.5" rx="1.5" fill="currentColor"/>
      <rect x="1.5" y="9"   width="5.5" height="5.5" rx="1.5" fill="currentColor"/>
      <rect x="9"   y="9"   width="5.5" height="5.5" rx="1.5" fill="currentColor" opacity=".55"/>
    </svg>
  ),
  Shield: ({ s=16 }) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M8 1.5 2 3.8v3.9C2 11.2 5 14 8 14.5 11 14 14 11.2 14 7.7V3.8Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/>
      <path d="m5.5 8 1.6 1.6L11 5.8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  Radar: ({ s=16 }) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="1.8" fill="currentColor"/>
      <circle cx="8" cy="8" r="4.5" stroke="currentColor" strokeWidth="1.1" strokeDasharray="2.5 1.8"/>
      <circle cx="8" cy="8" r="7"   stroke="currentColor" strokeWidth="0.9" opacity=".35"/>
      <line x1="8" y1="8" x2="12.5" y2="3.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" opacity=".7"/>
    </svg>
  ),
  CheckList: ({ s=16 }) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <rect x="2" y="2" width="12" height="12" rx="2" stroke="currentColor" strokeWidth="1.2"/>
      <path d="M5 8.4 6.8 10 11 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  Clock: ({ s=16 }) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.2"/>
      <path d="M8 5v3.2l2.2 1.4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
    </svg>
  ),
  Doc: ({ s=16 }) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <path d="M4 2h7l3 3v9H4V2Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round"/>
      <path d="M11 2v3h3" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round"/>
      <path d="M6.5 8h4M6.5 10.5h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/>
    </svg>
  ),
  Monitor: ({ s=16 }) => (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none">
      <rect x="1.5" y="2" width="13" height="9.5" rx="1.5" stroke="currentColor" strokeWidth="1.2"/>
      <path d="M5.5 14h5M8 11.5V14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
    </svg>
  ),
  Warning: ({ s=14 }) => (
    <svg width={s} height={s} viewBox="0 0 14 14" fill="none">
      <path d="M7 1.5 13.5 13H.5Z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round"/>
      <path d="M7 5.5v3M7 10.5v.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/>
    </svg>
  ),
  Refresh: ({ s=14 }) => (
    <svg width={s} height={s} viewBox="0 0 14 14" fill="none">
      <path d="M12 7A5 5 0 1 1 7 2a5 5 0 0 1 3.6 1.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <path d="M10 1.5V4h2.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
  Arrow: ({ s=12 }) => (
    <svg width={s} height={s} viewBox="0 0 12 12" fill="none">
      <path d="M2.5 6h7M6 2.5 9.5 6 6 9.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  ),
};

// ════════════════════════════════════════════════════════════
// SVG CHARTS
// ════════════════════════════════════════════════════════════

/** Donut chart using stroke-dasharray technique */
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

/** Arc gauge (0-100, higher = worse) */
function ScoreArc({ score, maxScore = 100 }) {
  const pct   = Math.min((score || 0) / (maxScore || 100), 1);
  const r     = 40;
  const circ  = 2 * Math.PI * r;
  const arc   = circ * 0.72;               // 260° sweep
  const fill  = pct * arc;
  const color = pct >= 0.7 ? C.critical : pct >= 0.4 ? C.medium : C.green;
  const cx = 52, cy = 58;

  return (
    <svg width="104" height="90" viewBox="0 0 104 90">
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#182034" strokeWidth="9"
        strokeDasharray={`${arc} ${circ - arc}`}
        strokeDashoffset={circ * 0.14}
        transform={`rotate(-130 ${cx} ${cy})`}
        strokeLinecap="round"
      />
      {/* Fill */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="9"
        strokeDasharray={`${fill} ${circ - fill}`}
        strokeDashoffset={circ * 0.14}
        transform={`rotate(-130 ${cx} ${cy})`}
        strokeLinecap="round"
        style={{ transition: 'stroke-dasharray .6s ease, stroke .4s ease', filter: `drop-shadow(0 0 5px ${color})` }}
      />
      {/* Labels */}
      <text x={cx} y={cy + 5} textAnchor="middle" fill={C.txt1} fontSize="19" fontWeight="700"
        fontFamily="Inter">{Math.round(score || 0)}</text>
      <text x={cx} y={cy + 17} textAnchor="middle" fill={C.txt3} fontSize="8.5"
        letterSpacing="1.2" fontFamily="Inter">SCORE</text>
    </svg>
  );
}

// ════════════════════════════════════════════════════════════
// REUSABLE UI ATOMS
// ════════════════════════════════════════════════════════════

function SevTag({ severity }) {
  const c = SEV[severity] || { color: '#64748b', bg: 'rgba(100,116,139,.1)' };
  return (
    <span style={{
      background: c.bg, color: c.color,
      padding: '1.5px 7px', borderRadius: 4,
      fontSize: 10, fontWeight: 700,
      textTransform: 'uppercase', letterSpacing: '.6px',
      display: 'inline-block', lineHeight: '18px',
    }}>{severity}</span>
  );
}

function StatusBadge({ status }) {
  const c = STATUS[status] || { color: '#64748b', bg: 'rgba(100,116,139,.1)' };
  const pulse = status === 'RUNNING';
  return (
    <span style={{
      background: c.bg, color: c.color,
      padding: '2px 8px', borderRadius: 4,
      fontSize: 11, fontWeight: 600,
      display: 'inline-flex', alignItems: 'center', gap: 5,
    }}>
      {pulse && (
        <span style={{
          width: 6, height: 6, borderRadius: '50%', background: c.color,
          display: 'inline-block', animation: 'pulse-dot 1.4s ease infinite',
          boxShadow: `0 0 5px ${c.color}`,
        }} />
      )}
      {status}
    </span>
  );
}

function ScanTypeBadge({ type }) {
  const map = { services: { color: C.blue, bg: 'rgba(79,131,255,.12)' }, cis: { color: C.purple, bg: 'rgba(124,92,252,.12)' } };
  const c = map[type] || { color: C.txt3, bg: 'rgba(100,116,139,.1)' };
  return (
    <span style={{ background: c.bg, color: c.color, padding: '1.5px 7px', borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.6px' }}>
      {type === 'cis' ? 'CIS' : 'SERVICES'}
    </span>
  );
}

/** Glassy panel card */
function Panel({ title, icon, extra, children, style = {}, bodyPad = '14px 16px' }) {
  return (
    <div style={{
      background: C.bgSurface,
      border: `1px solid ${C.border}`,
      borderRadius: 10, overflow: 'hidden',
      ...style,
    }}>
      {(title || extra) && (
        <div style={{
          padding: '11px 16px', display: 'flex',
          alignItems: 'center', justifyContent: 'space-between',
          borderBottom: `1px solid ${C.border}`,
          background: C.bgRaised,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, color: C.txt1 }}>
            {icon && <span style={{ color: C.accent, display: 'flex' }}>{icon}</span>}
            <span style={{ fontSize: 12, fontWeight: 600 }}>{title}</span>
          </div>
          {extra}
        </div>
      )}
      <div style={{ padding: bodyPad }}>{children}</div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════
// HOOKS
// ════════════════════════════════════════════════════════════

function usePoll(scanId, onDone) {
  const [detail, setDetail] = useState(null);
  const onDoneRef  = useRef(onDone);
  const doneRef    = useRef(false);
  const timerRef   = useRef(null);

  useEffect(() => { onDoneRef.current = onDone; }, [onDone]);

  useEffect(() => {
    if (!scanId) { setDetail(null); doneRef.current = false; return; }
    doneRef.current = false;

    const tick = () =>
      api(`/api/scans/${scanId}`).then(data => {
        setDetail(data);
        const st = data?.job?.status || data?.scan?.status;
        if ((st === 'COMPLETED' || st === 'FAILED') && !doneRef.current) {
          doneRef.current = true;
          clearInterval(timerRef.current);
          onDoneRef.current?.();
        }
      }).catch(() => {});

    tick();
    timerRef.current = setInterval(tick, 1600);
    return () => clearInterval(timerRef.current);
  }, [scanId]);

  return detail;
}

// ════════════════════════════════════════════════════════════
// FINDINGS LIST
// ════════════════════════════════════════════════════════════

function FindingsList({ findings }) {
  if (!findings?.length) return (
    <div style={{ padding: '40px 0', textAlign: 'center', color: C.txt3 }}>
      <div style={{ fontSize: 30, marginBottom: 8, opacity: .35 }}>🛡️</div>
      <div style={{ fontSize: 13 }}>No findings to display</div>
    </div>
  );

  return (
    <div>
      {findings.map((f, i) => {
        const c  = SEV[f.severity] || { color: '#64748b', bg: 'rgba(100,116,139,.08)' };
        const isLast = i === findings.length - 1;
        return (
          <div key={i} style={{
            display: 'flex', gap: 12, padding: '13px 0',
            borderBottom: isLast ? 'none' : `1px solid ${C.border}`,
            animation: `fade-in .2s ease ${(i * .04).toFixed(2)}s both`,
          }}>
            {/* Severity bar */}
            <div style={{ width: 3, borderRadius: 2, background: c.color, flexShrink: 0, alignSelf: 'stretch', opacity: .8 }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              {/* Title row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5, flexWrap: 'wrap' }}>
                <SevTag severity={f.severity} />
                <span style={{ fontSize: 12.5, fontWeight: 600, color: C.txt1, fontFamily: C.txtMono, wordBreak: 'break-all' }}>
                  {f.title}
                </span>
              </div>
              {/* Evidence */}
              <div style={{ fontSize: 12, color: C.txt2, marginBottom: 4, lineHeight: 1.55, wordBreak: 'break-word' }}>
                {f.evidence}
              </div>
              {/* Fix */}
              {f.fix && (
                <div style={{ fontSize: 11, color: C.txt3, lineHeight: 1.5, display: 'flex', gap: 5 }}>
                  <span style={{ color: C.green, fontWeight: 600, flexShrink: 0 }}>Fix:</span>
                  <span style={{ wordBreak: 'break-word' }}>{f.fix}</span>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ════════════════════════════════════════════════════════════
// SCAN PROGRESS WIDGET
// ════════════════════════════════════════════════════════════

function ScanProgressWidget({ job, style }) {
  if (!job) return null;
  const pct    = job.percent || 0;
  const isRun  = job.status === 'RUNNING';
  const isFail = job.status === 'FAILED';

  return (
    <div style={{ background: C.bgCard, borderRadius: 9, padding: '14px 16px', ...style }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: C.txt2, textTransform: 'uppercase', letterSpacing: '.7px' }}>
          {isRun ? '⟳ Scanning…' : isFail ? '✕ Failed' : '✓ Complete'}
        </span>
        <span style={{ fontSize: 12, fontWeight: 700, color: C.txt1, fontFamily: C.txtMono }}>{pct}%</span>
      </div>

      {/* Animated top bar for running */}
      {isRun && <div className="progress-gradient-bar" style={{ marginBottom: 8 }} />}

      <Progress
        percent={pct}
        status={isFail ? 'exception' : isRun ? 'active' : 'success'}
        showInfo={false}
        size={['100%', 5]}
        strokeColor={isFail ? C.red : { from: C.accent, to: C.accentEnd }}
        trailColor="#182034"
      />

      {/* Stage text */}
      {job.stage && (
        <div style={{
          marginTop: 10, fontSize: 11, color: C.txt2,
          fontFamily: C.txtMono, display: 'flex', alignItems: 'center', gap: 6,
        }}>
          {isRun && <span style={{ color: C.accent, animation: 'blink 1.1s step-end infinite' }}>▶</span>}
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{job.stage}</span>
        </div>
      )}
    </div>
  );
}

// ════════════════════════════════════════════════════════════
// PAGE — DASHBOARD
// ════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════
// PAGE — SCAN (services / cis)
// ════════════════════════════════════════════════════════════

function ScanPage({ type, onChanged, onOpen }) {
  const [scanId,     setScanId]     = useState(null);
  const [loading,    setLoading]    = useState(false);
  const [benchmarks, setBenchmarks] = useState([]);
  const detail  = usePoll(scanId, onChanged);
  const isRun   = detail?.job?.status === 'RUNNING';
  const isDone  = detail?.scan?.status === 'COMPLETED' || detail?.scan?.status === 'FAILED';

  useEffect(() => {
    if (type === 'cis') api('/api/cis/benchmarks').then(setBenchmarks).catch(() => {});
  }, [type]);

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
          <Form layout="vertical" onFinish={start} initialValues={{ target: DEFAULT_TARGET }}>
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
                    <Form.Item label="Attacker LHOST" name="lhost" style={{ marginBottom: 0 }}>
                      <Input placeholder="Auto-detect IP" style={{ fontSize: 12 }} />
                    </Form.Item>
                    <Form.Item label="Attacker LPORT" name="lport" style={{ marginBottom: 0 }}>
                      <InputNumber placeholder="4444" style={{ width: '100%', fontSize: 12 }} />
                    </Form.Item>
                    <Form.Item label="Attack Threads" name="threads" style={{ marginBottom: 0 }}>
                      <InputNumber placeholder="7000" style={{ width: '100%', fontSize: 12 }} />
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
                ['Score',   <span style={{ fontFamily: C.txtMono, fontWeight: 700, fontSize: 14, color: (detail.scan.score||0) >= 55 ? C.high : C.green }}>{Math.round(detail.scan.score||0)}</span>],
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

// ════════════════════════════════════════════════════════════
// PAGE — HISTORY
// ════════════════════════════════════════════════════════════

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
      title: 'Score', width: 72, align: 'center',
      render: (_, r) => (
        <span style={{ fontFamily: C.txtMono, fontWeight: 700, fontSize: 14, color: (r.score||0) >= 55 ? C.high : C.green }}>
          {Math.round(r.score || 0)}
        </span>
      ),
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

// ════════════════════════════════════════════════════════════
// PAGE — REPORT
// ════════════════════════════════════════════════════════════

function ReportPage({ scanId }) {
  const detail = usePoll(scanId);

  if (!scanId) return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      justifyContent: 'center', minHeight: 320, color: C.txt3, gap: 14,
    }}>
      <Ico.Doc s={36} />
      <span style={{ fontSize: 13 }}>Select a scan from History to view its full report</span>
    </div>
  );

  if (!detail) return (
    <div style={{ textAlign: 'center', padding: '80px 0', color: C.txt3 }}>Loading report…</div>
  );

  const { scan, findings, job } = detail;
  const summary = scan?.summary || {};
  const sevCounts = {};
  (findings || []).forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });
  const duration = scan?.completed_at
    ? Math.round((new Date(scan.completed_at) - new Date(scan.created_at)) / 1000)
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* ── Scan header card ── */}
      <div style={{ display: 'flex', gap: 14 }}>
        {/* Meta */}
        <Panel style={{ flex: 1 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 18, fontWeight: 700, color: C.txt1, fontFamily: C.txtMono, marginBottom: 8 }}>
                {scan?.target || '—'}
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
                <ScanTypeBadge type={scan?.type} />
                <StatusBadge status={scan?.status} />
                {summary.benchmark && (
                  <span style={{ background: 'rgba(79,131,255,.08)', border: `1px solid rgba(79,131,255,.15)`, borderRadius: 4, padding: '1.5px 7px', fontSize: 10, fontWeight: 600, color: C.txt2, fontFamily: C.txtMono }}>
                    {summary.benchmark}
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', gap: 22, flexWrap: 'wrap' }}>
                {[
                  ['Scan ID', (scan?.id || '').slice(0, 8) + '…'],
                  ['Started', dayjs(scan?.created_at).format('YYYY-MM-DD HH:mm:ss')],
                  ['Duration', duration != null ? `${duration}s` : '—'],
                  ['Findings', (findings || []).length],
                ].map(([lbl, val]) => (
                  <div key={lbl}>
                    <div style={{ fontSize: 9.5, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 2 }}>{lbl}</div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: C.txt2, fontFamily: C.txtMono }}>{val}</div>
                  </div>
                ))}
              </div>
            </div>
            <ScoreArc score={scan?.score || 0} maxScore={100} />
          </div>
        </Panel>

        {/* Severity breakdown */}
        <Panel title="Severity Breakdown" style={{ width: 210 }} bodyPad="12px 14px">
          {['critical', 'high', 'medium', 'low'].map(sev => {
            const cnt = sevCounts[sev] || 0;
            const max = Math.max(...Object.values(sevCounts), 1);
            return (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <div style={{ width: 56 }}><SevTag severity={sev} /></div>
                <div style={{ flex: 1, height: 4, borderRadius: 2, background: '#182034' }}>
                  <div style={{
                    height: '100%', borderRadius: 2, background: (SEV[sev] || {}).color,
                    width: `${(cnt / max) * 100}%`, transition: 'width .5s ease',
                  }} />
                </div>
                <span style={{ fontSize: 12, fontWeight: 700, color: C.txt1, fontFamily: C.txtMono, minWidth: 18, textAlign: 'right' }}>{cnt}</span>
              </div>
            );
          })}
        </Panel>
      </div>

      {/* ── CIS stats row ── */}
      {scan?.type === 'cis' && typeof summary.rules === 'number' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
          {[
            ['Rules Checked', summary.rules,   C.accent],
            ['Passed',        summary.passed,  C.green],
            ['Failed',        summary.failed,  C.red],
            ['Skipped',       summary.skipped, C.medium],
          ].map(([lbl, val, color]) => (
            <div key={lbl} style={{
              background: C.bgSurface, border: `1px solid ${C.border}`, borderRadius: 9,
              padding: '12px 14px', position: 'relative', overflow: 'hidden',
            }}>
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: color, borderRadius: '9px 9px 0 0' }} />
              <div style={{ fontSize: 10, color: C.txt3, textTransform: 'uppercase', letterSpacing: '.8px', marginBottom: 5 }}>{lbl}</div>
              <div style={{ fontSize: 26, fontWeight: 700, color, fontVariantNumeric: 'tabular-nums' }}>{val ?? '—'}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── Services & Modules stats row ── */}
      {scan?.type === 'services' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          {/* Detected Services */}
          <Panel title="Detected Services" icon={<Ico.Radar />}>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {summary.detectedServices && summary.detectedServices.length > 0 ? (
                summary.detectedServices.map(svc => (
                  <span key={svc} style={{ background: '#182034', border: `1px solid ${C.border}`, color: C.txt1, borderRadius: 5, padding: '3px 8px', fontSize: 11, fontWeight: 600, fontFamily: C.txtMono }}>
                    {svc}
                  </span>
                ))
              ) : (
                <span style={{ color: C.txt3, fontSize: 11 }}>No services detected.</span>
              )}
            </div>
          </Panel>
          {/* Metasploit Modules Used */}
          <Panel title="Metasploit Modules Executed" icon={<Ico.CheckList />}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {summary.modulesUsed && summary.modulesUsed.length > 0 ? (
                summary.modulesUsed.map(mod => (
                  <span key={mod} style={{ background: '#182034', border: `1px solid ${C.border}`, color: C.txt1, borderRadius: 5, padding: '3px 8px', fontSize: 11, fontWeight: 600, fontFamily: C.txtMono, display: 'inline-block', width: 'fit-content' }}>
                    {mod}
                  </span>
                ))
              ) : (
                <span style={{ color: C.txt3, fontSize: 11 }}>No Metasploit modules were executed.</span>
              )}
            </div>
          </Panel>
        </div>
      )}

      {/* ── Findings ── */}
      <Panel title={`Findings (${(findings || []).length})`} icon={<Ico.Warning />}>
        {job?.status === 'RUNNING' && <ScanProgressWidget job={job} style={{ marginBottom: 14 }} />}
        <FindingsList findings={findings} />
      </Panel>
    </div>
  );
}

// ════════════════════════════════════════════════════════════
// PAGE — SYSTEM INFO
// ════════════════════════════════════════════════════════════

function SystemPage() {
  const [info,    setInfo]    = useState(null);
  const [loading, setLoading] = useState(false);

  const collect = async () => {
    setLoading(true);
    try {
      setInfo(await api('/api/system/info'));
    } catch (e) {
      message.error(e.message);
    } finally {
      setLoading(false);
    }
  };

  const rows = info ? [
    ['Hostname',      info.CsName],
    ['OS Name',       info.OsName],
    ['OS Version',    info.OsVersion],
    ['Product Name',  info.WindowsProductName],
    ['Architecture',  info.OsArchitecture],
  ] : [];

  return (
    <Panel title="System Information" icon={<Ico.Monitor />}
      extra={<Button size="small" type="primary" loading={loading} onClick={collect}>Collect Info</Button>}
    >
      {!info ? (
        <div style={{ textAlign: 'center', padding: '56px 0', color: C.txt3 }}>
          <div style={{ fontSize: 36, opacity: .3, marginBottom: 14 }}>🖥️</div>
          <div style={{ fontSize: 13, marginBottom: 18 }}>
            Click <strong style={{ color: C.txt2 }}>Collect Info</strong> to gather system data via PowerShell
          </div>
          <Button type="primary" loading={loading} onClick={collect} size="large">Collect Info</Button>
        </div>
      ) : (
        <div style={{ borderRadius: 8, overflow: 'hidden', border: `1px solid ${C.border}` }}>
          {rows.map(([lbl, val], i) => (
            <div key={lbl} style={{ display: 'flex', background: i % 2 === 0 ? C.bgCard : C.bgSurface }}>
              <div style={{
                width: 170, padding: '11px 14px', fontSize: 11, fontWeight: 600,
                color: C.txt3, textTransform: 'uppercase', letterSpacing: '.6px', flexShrink: 0,
              }}>{lbl}</div>
              <div style={{
                flex: 1, padding: '11px 14px', fontSize: 13, color: C.txt1,
                fontFamily: C.txtMono, borderLeft: `1px solid ${C.border}`,
              }}>{val || '—'}</div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

// ════════════════════════════════════════════════════════════
// APP SHELL
// ════════════════════════════════════════════════════════════

const NAV = [
  { key: 'dashboard', label: 'Dashboard',     Icon: Ico.Dashboard,  sec: null },
  { key: 'services',  label: 'Service Scan',  Icon: Ico.Radar,      sec: 'Scanning' },
  { key: 'cis',       label: 'CIS Audit',     Icon: Ico.CheckList,  sec: 'Scanning' },
  { key: 'history',   label: 'History',       Icon: Ico.Clock,      sec: 'Reports' },
  { key: 'report',    label: 'Last Report',   Icon: Ico.Doc,        sec: 'Reports' },
  { key: 'system',    label: 'System Info',   Icon: Ico.Monitor,    sec: 'System' },
];

const PAGE_TITLE = {
  dashboard: 'Security Dashboard',
  services:  'Service & CVE Scan',
  cis:       'CIS Benchmark Audit',
  history:   'Scan History',
  report:    'Scan Report',
  system:    'System Information',
};

function NavItem({ item, active, onClick }) {
  const [hover, setHover] = useState(false);
  return (
    <div
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 9, padding: '8px 10px',
        borderRadius: 7, cursor: 'pointer', marginBottom: 1, position: 'relative',
        background: active ? 'rgba(79,131,255,.12)' : hover ? 'rgba(79,131,255,.06)' : 'transparent',
        color: active ? C.accent : hover ? C.txt1 : C.txt2,
        fontSize: 13, fontWeight: 500, transition: 'all .12s ease',
      }}
    >
      {active && (
        <div style={{
          position: 'absolute', left: 0, top: '18%', bottom: '18%',
          width: 2.5, background: C.accent, borderRadius: '0 3px 3px 0',
        }} />
      )}
      <item.Icon />
      <span>{item.label}</span>
    </div>
  );
}

function StartupSplash() {
  return (
    <div style={{
      minHeight: '100vh',
      width: '100vw',
      background: C.bgBase,
      color: C.txt1,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      overflow: 'hidden',
      fontFamily: "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    }}>
      <style>{`
        @keyframes startup-ring {
          0% { transform: scale(.5); opacity: 0; }
          20% { opacity: 1; }
          100% { transform: scale(1.15); opacity: 0; }
        }
        @keyframes startup-sweep {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes startup-pulse {
          0%, 100% { opacity: .55; }
          50% { opacity: 1; }
        }
      `}</style>

      <div style={{
        position: 'relative',
        width: 176,
        height: 176,
        marginBottom: 34,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}>
        {[0, 1, 2, 3].map(i => (
          <div key={i} style={{
            position: 'absolute',
            width: 62 + i * 38,
            height: 62 + i * 38,
            borderRadius: '50%',
            border: '1px solid rgba(79,131,255,.32)',
            animation: `startup-ring 3s ease-out ${i * .45}s infinite`,
          }} />
        ))}
        <div style={{
          position: 'absolute',
          width: 176,
          height: 176,
          borderRadius: '50%',
          animation: 'startup-sweep 4s linear infinite',
        }}>
          <div style={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            width: 88,
            height: 2,
            background: 'linear-gradient(90deg, rgba(79,131,255,.75), transparent)',
            transformOrigin: 'left center',
          }} />
        </div>
        <div style={{
          width: 58,
          height: 58,
          borderRadius: 14,
          background: C.gradient,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: `0 0 42px ${C.accentGlow}`,
          zIndex: 2,
        }}>
          <Ico.Shield s={28} />
        </div>
      </div>

      <div style={{ fontSize: 26, fontWeight: 700, marginBottom: 6 }}>VulnMngSys</div>
      <div style={{
        fontSize: 12,
        color: C.txt3,
        textTransform: 'uppercase',
        letterSpacing: 2,
        marginBottom: 42,
      }}>
        Windows Security Platform
      </div>

      <div style={{ width: 320, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: C.txt2, fontSize: 13 }}>
          <span style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: C.accent,
            boxShadow: `0 0 8px ${C.accent}`,
            animation: 'startup-pulse 1.2s ease-in-out infinite',
          }} />
          <span>Dang khoi dong backend va Metasploit...</span>
        </div>
        <div style={{
          width: '100%',
          height: 3,
          borderRadius: 2,
          background: 'rgba(79,131,255,.13)',
          overflow: 'hidden',
        }}>
          <div style={{
            width: '68%',
            height: '100%',
            borderRadius: 2,
            background: C.gradient,
            boxShadow: `0 0 8px ${C.accentGlow}`,
            transition: 'width .4s ease',
          }} />
        </div>
      </div>
    </div>
  );
}

function App() {
  const [startupReady, setStartupReady] = useState(false);
  const [tab,          setTab]         = useState('dashboard');
  const [refreshKey,   setRefreshKey]  = useState(0);
  const [selectedScan, setSelectedScan] = useState(null);
  const refresh = () => setRefreshKey(k => k + 1);

  useEffect(() => {
    let cancelled = false;
    let timer = null;

    const checkStatus = async () => {
      try {
        const status = await api('/api/status');
        if (!cancelled && status.ready === true) {
          setStartupReady(true);
          return;
        }
      } catch (_) {
        // Keep the splash visible while the backend is still starting.
      }
      if (!cancelled) timer = setTimeout(checkStatus, 1500);
    };

    checkStatus();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  const openReport = useCallback(id => {
    setSelectedScan(id);
    setTab('report');
  }, []);

  // Group nav by section
  const sections = useMemo(() => {
    const map = {};
    NAV.forEach(item => {
      const sec = item.sec || '__root__';
      if (!map[sec]) map[sec] = [];
      map[sec].push(item);
    });
    return Object.entries(map);
  }, []);

  if (!startupReady) return <StartupSplash />;

  return (
    <ConfigProvider theme={{
      algorithm: antdTheme.darkAlgorithm,
      token: {
        colorPrimary:      C.accent,
        colorBgBase:       C.bgSurface,
        colorTextBase:     C.txt1,
        borderRadius:      6,
        colorBorder:       C.border,
        colorBgContainer:  C.bgInput,
        colorBgElevated:   C.bgCard,
        colorBgSpotlight:  C.bgCard,
        colorText:         C.txt1,
        colorTextSecondary:C.txt2,
        colorTextTertiary: C.txt3,
        colorTextQuaternary: C.txt3,
        fontSize:          13,
        fontFamily:        "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
        colorSuccess:      C.green,
        colorError:        C.red,
        colorWarning:      C.medium,
        colorInfo:         C.accent,
      },
      components: {
        Table: {
          headerBg:         C.bgRaised,
          rowHoverBg:       'rgba(79,131,255,.05)',
          borderColor:      C.border,
          headerColor:      C.txt3,
          colorBgContainer: 'transparent',
        },
        Input:    { colorBgContainer: C.bgInput, colorBorder: C.border },
        Select:   { colorBgContainer: C.bgInput, optionSelectedBg: 'rgba(79,131,255,.12)' },
        Button:   { primaryColor: '#fff' },
        Progress: { colorInfo: C.accent },
        Pagination: { colorBgContainer: C.bgCard, colorBorder: C.border },
      },
    }}>
      <div style={{
        display: 'flex', height: '100vh', width: '100vw',
        overflow: 'hidden', background: C.bgBase,
      }}>
        {/* ══ SIDEBAR ══════════════════════════════════════════ */}
        <div style={{
          width: 212, minWidth: 212, background: C.bgSurface,
          borderRight: `1px solid ${C.border}`,
          display: 'flex', flexDirection: 'column', height: '100vh',
        }}>
          {/* Brand */}
          <div style={{ padding: '16px 14px 14px', borderBottom: `1px solid ${C.border}` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 32, height: 32, borderRadius: 8, flexShrink: 0,
                background: C.gradient, display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: `0 0 18px ${C.accentGlow}`,
              }}>
                <Ico.Shield />
              </div>
              <div>
                <div style={{ fontSize: 14.5, fontWeight: 700, color: C.txt1, lineHeight: 1.25 }}>VulnMngSys</div>
                <div style={{ fontSize: 10, color: C.txt3, fontFamily: C.txtMono }}>Windows Security</div>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <div style={{ flex: 1, padding: '10px 8px', overflowY: 'auto' }}>
            {sections.map(([sec, items]) => (
              <div key={sec}>
                {sec !== '__root__' && (
                  <div style={{
                    fontSize: 9.5, fontWeight: 700, color: C.txt3,
                    textTransform: 'uppercase', letterSpacing: '1.2px',
                    padding: '12px 10px 5px',
                  }}>{sec}</div>
                )}
                {items.map(item => (
                  <NavItem key={item.key} item={item} active={tab === item.key} onClick={() => setTab(item.key)} />
                ))}
              </div>
            ))}
          </div>

          {/* Status footer */}
          <div style={{ padding: '11px 14px', borderTop: `1px solid ${C.border}` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 11, color: C.txt3 }}>
              <div style={{
                width: 6, height: 6, borderRadius: '50%', background: C.green,
                boxShadow: `0 0 6px ${C.green}`,
                animation: 'pulse-dot 2s ease infinite',
              }} />
              Backend connected
            </div>
          </div>
        </div>

        {/* ══ MAIN ════════════════════════════════════════════ */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Top bar */}
          <div style={{
            height: 50, background: C.bgSurface, borderBottom: `1px solid ${C.border}`,
            display: 'flex', alignItems: 'center', padding: '0 20px', gap: 12, flexShrink: 0,
          }}>
            <span style={{ fontSize: 14, fontWeight: 600, color: C.txt1 }}>
              {PAGE_TITLE[tab]}
            </span>
            {tab === 'report' && selectedScan && (
              <span style={{ fontSize: 11, color: C.txt3, fontFamily: C.txtMono }}>
                #{selectedScan.slice(0, 8)}
              </span>
            )}

            {/* Right actions */}
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
              {(tab === 'dashboard' || tab === 'history') && (
                <button onClick={refresh} style={{
                  background: C.bgCard, border: `1px solid ${C.border}`,
                  color: C.txt2, borderRadius: 6, padding: '4px 12px',
                  fontSize: 12, cursor: 'pointer', fontFamily: 'Inter',
                  display: 'flex', alignItems: 'center', gap: 6,
                }}>
                  <Ico.Refresh /> Refresh
                </button>
              )}
              {/* Scan shortcut buttons */}
              {(tab === 'dashboard' || tab === 'history') && (
                <button onClick={() => setTab('services')} style={{
                  background: 'rgba(79,131,255,.1)', border: `1px solid rgba(79,131,255,.2)`,
                  color: C.accent, borderRadius: 6, padding: '4px 12px',
                  fontSize: 12, cursor: 'pointer', fontFamily: 'Inter', fontWeight: 600,
                }}>
                  + New Scan
                </button>
              )}
            </div>
          </div>

          {/* Page content */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 18 }}>
            {tab === 'dashboard' && <DashboardPage refreshKey={refreshKey} onOpen={openReport} />}
            {tab === 'services'  && <ScanPage key="services" type="services" onChanged={refresh} onOpen={openReport} />}
            {tab === 'cis'       && <ScanPage key="cis" type="cis" onChanged={refresh} onOpen={openReport} />}
            {tab === 'history'   && <HistoryPage refreshKey={refreshKey} onOpen={openReport} />}
            {tab === 'report'    && <ReportPage scanId={selectedScan} />}
            {tab === 'system'    && <SystemPage />}
          </div>
        </div>
      </div>
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
