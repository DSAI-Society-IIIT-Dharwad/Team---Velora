import { useState, useEffect } from "react"
import axios from "axios"

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
  SAFE:     "#6b7280",
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

export default function BlastRadius({ node, nodes, edges }) {
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)
  const [hops, setHops]         = useState(2)
  const [error, setError]       = useState("")

  useEffect(() => {
    if (!node) return
    fetchBlastRadius()
  }, [node?.id, hops])

  const fetchBlastRadius = async () => {
    setLoading(true)
    setError("")
    setResult(null)

    try {
      const res = await axios.post("/api/blast-radius", {
        node_id: node.id,
        nodes,
        edges,
        hops,
      })
      setResult(res.data)
    } catch (err) {
      setError("Failed to calculate blast radius.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div
      className="border-t flex flex-col"
      style={{ borderColor: "#f9731630" }}
    >
      {/* Header */}
      <div className="px-4 py-2 flex items-center justify-between"
        style={{ borderBottom: "1px solid #ffffff10" }}>
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-[#f97316] animate-pulse" />
          <span className="text-xs text-[#f97316] tracking-widest uppercase font-semibold">
            Blast Radius
          </span>
        </div>

        {/* Hop selector */}
        <div className="flex items-center gap-1">
          {[1, 2, 3].map(h => (
            <button
              key={h}
              onClick={() => setHops(h)}
              className="w-6 h-6 rounded text-[10px] font-bold transition-all"
              style={{
                background: hops === h ? "#f97316"    : "#ffffff10",
                color:      hops === h ? "white"      : "#ffffff40",
                border:     hops === h ? "none"       : "1px solid #ffffff10",
              }}
            >
              {h}
            </button>
          ))}
          <span className="text-[9px] text-white/30 ml-1">hops</span>
        </div>
      </div>

      {/* Content */}
      <div className="px-4 py-3 overflow-y-auto" style={{ maxHeight: "240px" }}>
        {loading && (
          <div className="flex items-center gap-2 text-xs text-[#f97316]">
            <svg className="animate-spin" width="12" height="12" viewBox="0 0 24 24"
              fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
            </svg>
            Calculating blast radius...
          </div>
        )}

        {error && (
          <div className="text-xs text-red-400">{error}</div>
        )}

        {result && !loading && (
          <div className="flex flex-col gap-3">

            {/* Summary */}
            <div className="flex items-center gap-3">
              <div className="flex flex-col items-center bg-[#f9731615] border border-[#f9731630] rounded px-3 py-2 flex-1">
                <span className="text-[#f97316] font-black text-xl">
                  {result.count}
                </span>
                <span className="text-white/40 text-[9px] tracking-widest uppercase">
                  Nodes at Risk
                </span>
              </div>
              <div className="flex flex-col items-center bg-[#ef444415] border border-[#ef444430] rounded px-3 py-2 flex-1">
                <span className="text-[#ef4444] font-black text-xl">
                  {result.total_exposure}
                </span>
                <span className="text-white/40 text-[9px] tracking-widest uppercase">
                  Exposure Score
                </span>
              </div>
            </div>

            {/* Reachable nodes */}
            {result.reachable.length === 0 ? (
              <div className="text-xs text-white/30 text-center py-2">
                No reachable nodes within {hops} hop{hops > 1 ? "s" : ""}
              </div>
            ) : (
              <div className="flex flex-col gap-1">
                <div className="text-[9px] text-white/30 tracking-widest uppercase mb-1">
                  Reachable Nodes
                </div>
                {result.reachable
                  .sort((a, b) => b.risk - a.risk)
                  .map((n) => (
                    <div
                      key={n.id}
                      className="flex items-center gap-2 bg-white/5 rounded px-2 py-1.5"
                    >
                      {/* Hop badge */}
                      <div
                        className="w-4 h-4 rounded-full flex items-center justify-center text-[8px] font-bold shrink-0"
                        style={{
                          background: "#f9731620",
                          border:     "1px solid #f9731640",
                          color:      "#f97316",
                        }}
                      >
                        {n.hop}
                      </div>

                      {/* Icon */}
                      <span className="text-xs shrink-0">
                        {TYPE_ICONS[n.type] || "●"}
                      </span>

                      {/* Name */}
                      <span className="text-[10px] text-white/70 font-mono flex-1 truncate">
                        {n.name}
                      </span>

                      {/* Risk */}
                      <span
                        className="text-[9px] font-bold shrink-0"
                        style={{
                          color: n.risk >= 70 ? "#ef4444"
                               : n.risk >= 40 ? "#f97316"
                               : n.risk >= 20 ? "#eab308"
                               : "#22c55e",
                        }}
                      >
                        {n.risk}
                      </span>
                    </div>
                  ))}
              </div>
            )}

            {/* Warning if high exposure */}
            {result.total_exposure >= 70 && (
              <div
                className="text-[10px] rounded px-2 py-1.5 leading-relaxed"
                style={{
                  background: "#ef444410",
                  border:     "1px solid #ef444430",
                  color:      "#ef4444",
                }}
              >
                ⚠ Critical blast radius — breaching this node exposes{" "}
                {result.count} resources with a combined risk of{" "}
                {result.total_exposure}.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}