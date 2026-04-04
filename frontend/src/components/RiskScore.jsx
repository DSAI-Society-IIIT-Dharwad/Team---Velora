export default function RiskScore({ score }) {
  const getColor = (s) => {
    if (s >= 70) return "#ef4444"
    if (s >= 40) return "#f97316"
    if (s >= 20) return "#eab308"
    return "#22c55e"
  }

  const getLabel = (s) => {
    if (s >= 70) return "CRITICAL"
    if (s >= 40) return "HIGH"
    if (s >= 20) return "MEDIUM"
    return "LOW"
  }

  const color = getColor(score)
  const label = getLabel(score)
  const circumference = 2 * Math.PI * 36
  const offset = circumference - (score / 100) * circumference

  return (
    <div className="flex flex-col gap-3">
      {/* Title */}
      <div className="text-xs text-[#00a0e9] tracking-widest uppercase font-semibold">
        Cluster Risk Score
      </div>

      {/* Circular gauge */}
      <div className="flex flex-col items-center gap-2">
        <svg width="100" height="100" viewBox="0 0 100 100">
          {/* Background circle */}
          <circle
            cx="50"
            cy="50"
            r="36"
            fill="none"
            stroke="#ffffff10"
            strokeWidth="8"
          />
          {/* Progress circle */}
          <circle
            cx="50"
            cy="50"
            r="36"
            fill="none"
            stroke={color}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            transform="rotate(-90 50 50)"
            style={{ transition: "stroke-dashoffset 1s ease" }}
          />
          {/* Score text */}
          <text
            x="50"
            y="46"
            textAnchor="middle"
            fill="white"
            fontSize="20"
            fontWeight="bold"
            fontFamily="Arial"
          >
            {score}
          </text>
          <text
            x="50"
            y="60"
            textAnchor="middle"
            fill="#ffffff60"
            fontSize="8"
            fontFamily="Arial"
          >
            / 100
          </text>
        </svg>

        {/* Severity label */}
        <div
          className="text-xs font-bold tracking-widest px-3 py-1 rounded"
          style={{ color, background: `${color}20`, border: `1px solid ${color}40` }}
        >
          {label}
        </div>
      </div>

      {/* Risk breakdown legend */}
      <div className="flex flex-col gap-1 mt-1">
        {[
          { label: "CRITICAL", color: "#ef4444", min: 70 },
          { label: "HIGH",     color: "#f97316", min: 40 },
          { label: "MEDIUM",   color: "#eab308", min: 20 },
          { label: "LOW",      color: "#22c55e", min: 0  },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-2">
            <div
              className="w-2 h-2 rounded-full"
              style={{ background: item.color }}
            />
            <span className="text-white/40 text-[10px] tracking-widest">
              {item.label}
            </span>
            <span className="text-white/20 text-[10px] ml-auto">
              {item.min}+
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}