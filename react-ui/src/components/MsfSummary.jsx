import { Space, Tag } from 'antd'

const PILL_CONFIG = {
  pass: { antColor: 'success', label: 'PASS' },
  fail: { antColor: 'error', label: 'FAIL' },
  warning: { antColor: 'warning', label: 'WARNING' },
  info: { antColor: 'processing', label: 'INFO' },
  skipped: { antColor: 'default', label: 'SKIPPED' },
  error: { antColor: 'volcano', label: 'ERROR' },
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
