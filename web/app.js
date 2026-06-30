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


/** Arc gauge representing compliance/safety ratio (higher = better) */
function ScoreArc({ score, maxScore = 100, type = 'services', summary = {} }) {
  let pct = 0;
  let label = "SAFE";
  
  if (type === 'cis' && summary && summary.rules > 0) {
    pct = (summary.passed || 0) / summary.rules;
    label = "PASS";
  } else if (type === 'services' && summary) {
    const total_det = summary.detectedServices?.length || 0;
    const affected = summary.modulesUsed?.length || 0;
    const clean = total_det > 0 ? Math.max(0, total_det - affected) : 1;
    pct = total_det > 0 ? (clean / total_det) : 1.0;
    label = "CLEAN";
  } else {
    pct = 1.0;
  }
  
  const val = Math.round(pct * 100);
  const r     = 40;
  const circ  = 2 * Math.PI * r;
  const arc   = circ * 0.72;               // 260° sweep
  const fill  = pct * arc;
  const color = pct >= 0.9 ? C.green : pct >= 0.7 ? C.medium : pct >= 0.4 ? C.high : C.critical;
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
      <text x={cx} y={cy + 5} textAnchor="middle" fill={C.txt1} fontSize="17" fontWeight="700"
        fontFamily={C.txtMono}>{val}%</text>
      <text x={cx} y={cy + 17} textAnchor="middle" fill={C.txt3} fontSize="8"
        letterSpacing="1.2" fontFamily="Inter">{label}</text>
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
// PAGES & VIEWS (Moved to web/views/ directory)
// ════════════════════════════════════════════════════════════


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
