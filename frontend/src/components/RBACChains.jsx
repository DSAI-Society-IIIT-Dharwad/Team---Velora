const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
}

const SEVERITY_BG = {
  CRITICAL: "#ef444415",
  HIGH:     "#f9731615",
  MEDIUM:   "#eab30815",
}

export default function RBACChains({ chains }) {
  if (!chains || chains.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3">
        <div className="text-white/10 text-sm tracking-widest uppercase">
          No RBAC chains detected
        </div>
        <div className="text-white/5 text-xs">
          Upload a YAML with ServiceAccounts and RoleBindings
        </div>
      </div>
    )
  }

  const critical = chains.filter(c => c.severity === "CRITICAL")
  const high     = chains.filter(c => c.severity === "HIGH")
  const medium   = chains.filter(c => c.severity === "MEDIUM")

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Header */}
      <div className="px-6 py-4 border-b border-white/10 shrink-0">
        <div className="flex items-center gap-2 mb-1">
          <div className="w-1.5 h-1.5 rounded-full bg-[#ef4444] animate-pulse" />
          <span className="text-xs text-[#ef4444] tracking-widest uppercase font-semibold">
            RBAC Privilege Chain Analysis
          </span>
        </div>
        <div className="text-white/40 text-xs mt-1">
          ServiceAccount → RoleBinding → ClusterRole privilege escalation paths
        </div>

        {/* Summary bar */}
        <div className="flex items-center gap-3 mt-3">
          {[
            { label: "Critical", count: critical.length, color: "#ef4444" },
            { label: "High",     count: high.length,     color: "#f97316" },
            { label: "Medium",   count: medium.length,   color: "#eab308" },
          ].map(item => (
            <div
              key={item.label}
              className="flex items-center gap-1.5 px-2 py-1 rounded"
              style={{
                background: `${item.color}15`,
                border:     `1px solid ${item.color}30`,
              }}
            >
              <span
                className="font-black text-sm"
                style={{ color: item.color }}
              >
                {item.count}
              </span>
              <span className="text-[10px] tracking-widest uppercase"
                style={{ color: `${item.color}80` }}>
                {item.label}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Chain list */}
      <div className="flex-1 overflow-y-auto px-6 py-4 flex flex-col gap-3">
        {chains.map((chain, i) => (
          <ChainCard key={i} chain={chain} index={i} />
        ))}
      </div>
    </div>
  )
}

function ChainCard({ chain, index }) {
  const color = SEVERITY_COLORS[chain.severity] || "#6b7280"
  const bg    = SEVERITY_BG[chain.severity]    || "#6b728015"

  return (
    <div
      className="rounded-lg p-4 flex flex-col gap-3"
      style={{
        background: bg,
        border:     `1px solid ${color}30`,
      }}
    >
      {/* Top row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className="text-[10px] font-black tracking-widest px-2 py-0.5 rounded"
            style={{
              color,
              background: `${color}20`,
              border:     `1px solid ${color}40`,
            }}
          >
            {chain.severity}
          </span>
          <span className="text-white/30 text-[10px]">
            Chain #{index + 1}
          </span>
        </div>
        <div
          className="text-sm font-black"
          style={{ color }}
        >
          {chain.chain_risk}
          <span className="text-[10px] font-normal text-white/30"> risk</span>
        </div>
      </div>

      {/* Chain visualization */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* ServiceAccount */}
        <div
          className="flex items-center gap-1.5 px-2 py-1 rounded"
          style={{
            background: "#eab30820",
            border:     "1px solid #eab30840",
          }}
        >
          <span className="text-xs">👤</span>
          <span className="text-[10px] font-mono text-[#eab308]">
            {chain.serviceaccount}
          </span>
        </div>

        {/* Arrow */}
        <div className="flex items-center">
          <svg width="32" height="12" viewBox="0 0 32 12">
            <line
              x1="0" y1="6" x2="24" y2="6"
              stroke={color}
              strokeWidth="1.5"
              strokeDasharray="3,2"
            />
            <polygon points="24,3 32,6 24,9" fill={color} />
          </svg>
        </div>

        {/* RBAC */}
        <div
          className="flex items-center gap-1.5 px-2 py-1 rounded"
          style={{
            background: `${color}20`,
            border:     `1px solid ${color}40`,
          }}
        >
          <span className="text-xs">🛡</span>
          <span
            className="text-[10px] font-mono"
            style={{ color }}
          >
            {chain.rbac}
          </span>
        </div>
      </div>

      {/* Description */}
      <div className="text-[10px] text-white/50 leading-relaxed">
        {chain.description}
      </div>

      {/* What this grants */}
      <div
        className="text-[10px] rounded px-2 py-1.5 leading-relaxed"
        style={{
          background: "#ffffff08",
          color:      "#ffffff60",
        }}
      >
        🔓 This chain grants <span style={{ color }} className="font-bold">
          elevated cluster permissions
        </span> — an attacker compromising{" "}
        <span className="text-white font-mono">{chain.serviceaccount}</span>{" "}
        can escalate to <span className="text-white font-mono">{chain.rbac}</span>{" "}
        and potentially achieve cluster-wide control.
      </div>
    </div>
  )
}