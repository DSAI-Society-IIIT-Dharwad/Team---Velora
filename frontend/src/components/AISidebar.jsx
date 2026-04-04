import { useEffect, useState } from "react"
import axios from "axios"

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
  SAFE:     "#6b7280",
  UNKNOWN:  "#6b7280",
}

const NODE_TYPE_LABELS = {
  pod:            "Pod / Container",
  service:        "Service / Ingress",
  secret:         "Secret",
  rbac:           "RBAC / ClusterRoleBinding",
  serviceaccount: "Service Account",
  networkpolicy:  "Network Policy",
  other:          "Resource",
}

export default function AISidebar({ node }) {
  const [loading, setLoading]           = useState(false)
  const [explanation, setExplanation]   = useState(null)
  const [error, setError]               = useState("")

  useEffect(() => {
    if (!node) return
    fetchExplanation()
  }, [node?.id])

  const fetchExplanation = async () => {
    setLoading(true)
    setError("")
    setExplanation(null)

    try {
      const res = await axios.post("/api/explain", {
        node_id:         node.id,
        node_type:       node.type,
        vulnerabilities: node.vulnerabilities || [],
      })
      setExplanation(res.data.explanation)
    } catch (err) {
      setError("Failed to fetch AI explanation. Is the backend running?")
    } finally {
      setLoading(false)
    }
  }

  const severity = explanation?.severity || (node.risk >= 70
    ? "CRITICAL" : node.risk >= 40
    ? "HIGH"     : node.risk >= 20
    ? "MEDIUM"   : node.risk > 0
    ? "LOW"      : "SAFE")

  const color = SEVERITY_COLORS[severity] || "#6b7280"

  return (
    <div className="h-full flex flex-col bg-[#0a0a0a] overflow-y-auto">
      {/* Header */}
      <div
        className="px-4 py-3 border-b"
        style={{ borderColor: `${color}40` }}
      >
        <div className="text-xs text-[#00a0e9] tracking-widest uppercase mb-1">
          AI Analysis
        </div>
        <div className="font-bold text-white text-sm truncate">
          {node.name}
        </div>
        <div className="text-white/40 text-xs mt-0.5">
          {NODE_TYPE_LABELS[node.type] || node.type}
        </div>
      </div>

      {/* Severity badge */}
      <div className="px-4 py-3 flex items-center gap-3">
        <div
          className="text-xs font-bold tracking-widest px-3 py-1 rounded"
          style={{
            color,
            background: `${color}20`,
            border:     `1px solid ${color}40`,
          }}
        >
          {severity}
        </div>
        <div className="text-white/40 text-xs">
          Risk Score: <span className="text-white font-bold">{node.risk}</span>
        </div>
      </div>

      {/* Vulnerabilities list */}
      {node.vulnerabilities && node.vulnerabilities.length > 0 && (
        <div className="px-4 pb-3">
          <div className="text-xs text-white/40 tracking-widest uppercase mb-2">
            Vulnerabilities Detected
          </div>
          <div className="flex flex-col gap-1">
            {node.vulnerabilities.map((v, i) => (
              <div
                key={i}
                className="flex items-start gap-2 text-xs text-white/70 bg-white/5 rounded px-2 py-1.5"
              >
                <span style={{ color: "#ef4444" }}>⚠</span>
                {v}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="border-t border-white/10 mx-4" />

      {/* AI Explanation */}
      <div className="px-4 py-3 flex flex-col gap-3 flex-1">
        {loading && (
          <div className="flex flex-col items-center gap-3 py-6">
            <NokiaLoader />
            <span className="text-xs text-[#00a0e9] tracking-widest animate-pulse">
              Analyzing with Groq AI...
            </span>
          </div>
        )}

        {error && (
          <div className="text-xs text-red-400 bg-red-400/10 rounded px-3 py-2">
            {error}
          </div>
        )}

        {explanation && !loading && (
          <>
            {/* Risk explanation */}
            <div>
              <div className="text-xs text-white/40 tracking-widest uppercase mb-2">
                Why This Is Dangerous
              </div>
              <div className="text-xs text-white/80 leading-relaxed bg-white/5 rounded px-3 py-2">
                {explanation.risk_explanation}
              </div>
            </div>

            {/* Fix */}
            <div>
              <div className="text-xs text-white/40 tracking-widest uppercase mb-2">
                Recommended Fix
              </div>
              <div
                className="text-xs leading-relaxed rounded px-3 py-2 font-mono whitespace-pre-wrap"
                style={{
                  background: "#00a0e910",
                  border:     "1px solid #00a0e930",
                  color:      "#00a0e9",
                }}
              >
                {explanation.fix}
              </div>
            </div>
          </>
        )}

        {/* No vulnerabilities */}
        {!loading && !error && node.vulnerabilities?.length === 0 && (
          <div className="text-xs text-green-400 bg-green-400/10 rounded px-3 py-2">
            ✓ No vulnerabilities detected on this node.
          </div>
        )}
      </div>

      {/* Nokia footer */}
      <div className="px-4 py-3 border-t border-white/10 flex items-center gap-2">
        <div className="w-1.5 h-1.5 rounded-full bg-[#00a0e9] animate-pulse" />
        <span className="text-[10px] text-white/20 tracking-widest">
          POWERED BY GROQ + LLAMA3
        </span>
      </div>
    </div>
  )
}

function NokiaLoader() {
  return (
    <div className="flex gap-1.5">
      {[0, 1, 2, 3, 4].map((i) => (
        <div
          key={i}
          className="w-1 rounded-full bg-[#00a0e9]"
          style={{
            height:          `${10 + i * 4}px`,
            animation:       "pulse 1s ease-in-out infinite",
            animationDelay:  `${i * 0.15}s`,
            opacity:         0.4 + i * 0.15,
          }}
        />
      ))}
    </div>
  )
}