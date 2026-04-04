const TYPE_COLORS = {
  pod:            "#00a0e9",
  service:        "#a855f7",
  secret:         "#f97316",
  rbac:           "#ef4444",
  serviceaccount: "#eab308",
  networkpolicy:  "#22c55e",
  other:          "#6b7280",
}

const TYPE_ICONS = {
  pod:            "⬡",
  service:        "◈",
  secret:         "🔑",
  rbac:           "🛡",
  serviceaccount: "👤",
  networkpolicy:  "🔒",
  other:          "●",
}

export default function KillChain({ attackPath, nodes, onNodeClick }) {
  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]))
  const steps   = attackPath.map(id => nodeMap[id]).filter(Boolean)

  if (steps.length === 0) return null

  return (
    <div
      className="border-t px-4 py-3"
      style={{ borderColor: "#ef444430", background: "#0a0a0a" }}
    >
      {/* Title */}
      <div className="flex items-center gap-2 mb-3">
        <div className="w-1.5 h-1.5 rounded-full bg-[#ef4444] animate-pulse" />
        <span className="text-xs text-[#ef4444] tracking-widest uppercase font-semibold">
          Attacker Kill Chain
        </span>
        <span className="text-xs text-white/20 ml-auto">
          {steps.length} step{steps.length > 1 ? "s" : ""}
        </span>
      </div>

      {/* Steps */}
      <div className="flex items-center gap-0 overflow-x-auto pb-1">
        {steps.map((node, i) => (
          <div key={node.id} className="flex items-center">
            {/* Step card */}
            <button
              onClick={() => onNodeClick(node)}
              className="flex flex-col items-center gap-1 px-3 py-2 rounded transition-all hover:bg-white/5 group min-w-fit"
            >
              {/* Step number */}
              <div className="flex items-center gap-1.5">
                <div
                  className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold"
                  style={{
                    background: i === 0
                      ? "#22c55e20"
                      : i === steps.length - 1
                      ? "#ef444420"
                      : "#ef444415",
                    border: `1px solid ${
                      i === 0
                        ? "#22c55e60"
                        : i === steps.length - 1
                        ? "#ef444460"
                        : "#ef444440"
                    }`,
                    color: i === 0
                      ? "#22c55e"
                      : "#ef4444",
                  }}
                >
                  {i + 1}
                </div>

                {/* Entry / Target badge */}
                {i === 0 && (
                  <span className="text-[9px] text-green-400 tracking-widest uppercase">
                    Entry
                  </span>
                )}
                {i === steps.length - 1 && i !== 0 && (
                  <span className="text-[9px] text-red-400 tracking-widest uppercase">
                    Target
                  </span>
                )}
              </div>

              {/* Node icon + name */}
              <div className="flex items-center gap-1">
                <span style={{ fontSize: "12px" }}>
                  {TYPE_ICONS[node.type] || "●"}
                </span>
                <span
                  className="text-[10px] font-mono group-hover:text-white transition-colors"
                  style={{ color: TYPE_COLORS[node.type] || "#6b7280" }}
                >
                  {node.name.length > 12
                    ? node.name.slice(0, 12) + "…"
                    : node.name}
                </span>
              </div>

              {/* Risk score */}
              <div
                className="text-[9px] px-1.5 py-0.5 rounded"
                style={{
                  color: node.risk >= 70
                    ? "#ef4444"
                    : node.risk >= 40
                    ? "#f97316"
                    : "#eab308",
                  background: node.risk >= 70
                    ? "#ef444415"
                    : node.risk >= 40
                    ? "#f9731615"
                    : "#eab30815",
                }}
              >
                risk: {node.risk}
              </div>
            </button>

            {/* Arrow between steps */}
            {i < steps.length - 1 && (
              <div className="flex items-center px-1">
                <svg width="24" height="12" viewBox="0 0 24 12">
                  <line
                    x1="0" y1="6" x2="18" y2="6"
                    stroke="#ef444460"
                    strokeWidth="1.5"
                    strokeDasharray="3,2"
                  />
                  <polygon
                    points="18,3 24,6 18,9"
                    fill="#ef444460"
                  />
                </svg>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}