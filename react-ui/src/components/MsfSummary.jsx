import { Space, Tag } from 'antd'

const PILL_CONFIG = {
  high: { antColor: 'error', label: 'HIGH' },
  medium: { antColor: 'warning', label: 'MEDIUM' },
  low: { antColor: 'gold', label: 'LOW' },
  info: { antColor: 'processing', label: 'INFO' },
}

export function ScoreRing({ score, label, color }) {
  const radius = 52
  const stroke = 9
  const circumference = 2 * Math.PI * radius
  const progress = ((score ?? 0) / 100) * circumference
  const colors = { green: '#16a34a', orange: '#d97706', red: '#dc2626' }
  const ringColor = colors[color] || '#0f766e'

  return (
    <div className="msf-score-ring">
      <svg width={124} height={124}>
        <circle cx={62} cy={62} r={radius} fill="none" stroke="#e2e8f0" strokeWidth={stroke} />
        <circle
          cx={62}
          cy={62}
          r={radius}
          fill="none"
          stroke={ringColor}
          strokeWidth={stroke}
          strokeDasharray={`${progress} ${circumference}`}
          strokeLinecap="round"
          transform="rotate(-90 62 62)"
        />
        <text x={62} y={58} textAnchor="middle" fill={ringColor} fontSize="22" fontWeight="700">
          {score ?? 0}
        </text>
        <text x={62} y={76} textAnchor="middle" fill="#64748b" fontSize="11">/ 100</text>
      </svg>
      <Tag color={color === 'green' ? 'success' : color === 'orange' ? 'warning' : 'error'}>{label}</Tag>
    </div>
  )
}

export function SummaryPills({ summary }) {
  return (
    <Space wrap size={8}>
      {Object.entries(PILL_CONFIG).map(([key, cfg]) => {
        const count = summary?.[key] ?? 0
        return count ? (
          <Tag key={key} color={cfg.antColor} className="msf-summary-pill">
            {cfg.label}: {count}
          </Tag>
        ) : null
      })}
    </Space>
  )
}

export function SeverityPieChart({ summary }) {
  const high = summary?.high ?? 0
  const medium = summary?.medium ?? 0
  const low = summary?.low ?? 0
  const info = summary?.info ?? 0
  const total = high + medium + low + info

  if (total === 0) {
    return (
      <div style={{ padding: '8px 16px', color: '#64748b', fontStyle: 'italic' }}>
        No findings to display.
      </div>
    )
  }

  const r = 38
  const strokeWidth = 12
  const c = 2 * Math.PI * r

  const colors = {
    high: '#dc2626',
    medium: '#ea580c',
    low: '#ca8a04',
    info: '#2563eb',
  }

  const items = [
    { key: 'high', value: high, color: colors.high, label: 'High' },
    { key: 'medium', value: medium, color: colors.medium, label: 'Medium' },
    { key: 'low', value: low, color: colors.low, label: 'Low' },
    { key: 'info', value: info, color: colors.info, label: 'Info' },
  ].filter(item => item.value > 0)

  let accumulatedPercent = 0

  return (
    <div className="severity-pie-chart-container" style={{
      display: 'flex',
      alignItems: 'center',
      gap: '20px',
      background: 'rgba(255, 255, 255, 0.6)',
      backdropFilter: 'blur(8px)',
      border: '1px solid rgba(226, 232, 240, 0.8)',
      padding: '12px 20px',
      borderRadius: '12px',
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -1px rgba(0, 0, 0, 0.03)',
      maxWidth: '360px',
      marginTop: '8px'
    }}>
      <div style={{ position: 'relative', width: '92px', height: '92px', flexShrink: 0 }}>
        <svg width={92} height={92} viewBox="0 0 92 92">
          <circle cx={46} cy={46} r={r} fill="none" stroke="#f1f5f9" strokeWidth={strokeWidth} />
          {items.map((item) => {
            const percent = (item.value / total) * 100
            const strokeLength = (percent / 100) * c
            const strokeOffset = c - (accumulatedPercent / 100) * c
            accumulatedPercent += percent
            return (
              <circle
                key={item.key}
                cx={46}
                cy={46}
                r={r}
                fill="none"
                stroke={item.color}
                strokeWidth={strokeWidth}
                strokeDasharray={`${strokeLength} ${c}`}
                strokeDashoffset={strokeOffset}
                transform="rotate(-90 46 46)"
                strokeLinecap="butt"
                style={{ transition: 'stroke-dashoffset 0.4s ease' }}
              />
            )
          })}
        </svg>
        <div style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          pointerEvents: 'none'
        }}>
          <span style={{ fontSize: '15px', fontWeight: '800', color: '#0f172a', lineHeight: '1' }}>{total}</span>
          <span style={{ fontSize: '8px', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px', marginTop: '2px', fontWeight: '600' }}>Total</span>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', flexGrow: 1 }}>
        {items.map(item => (
          <div key={item.key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', backgroundColor: item.color }} />
              <span style={{ fontWeight: '600', color: '#475569' }}>{item.label}</span>
            </div>
            <span style={{ color: '#0f172a', fontWeight: '500' }}>
              {item.value} <span style={{ color: '#94a3b8', fontSize: '10px' }}>({Math.round((item.value / total) * 100)}%)</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

