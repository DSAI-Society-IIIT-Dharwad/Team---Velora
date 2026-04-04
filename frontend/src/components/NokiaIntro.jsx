import { useEffect, useState, useRef } from "react"

const RADAR_NODES = [
  { a: 35,  r: 0.52, c: "#00a0e9" },
  { a: 100, r: 0.38, c: "#ef4444" },
  { a: 155, r: 0.61, c: "#f97316" },
  { a: 210, r: 0.44, c: "#00a0e9" },
  { a: 265, r: 0.58, c: "#a855f7" },
  { a: 315, r: 0.35, c: "#ef4444" },
  { a: 20,  r: 0.68, c: "#f97316" },
  { a: 180, r: 0.30, c: "#00a0e9" },
]

export default function NokiaIntro({ onComplete }) {
  const [phase, setPhase]             = useState("black")
  const [activeNodes, setActiveNodes] = useState([])
  const [sweep, setSweep]             = useState(0)
  const rafRef = useRef(null)
  const t0Ref  = useRef(null)

  useEffect(() => {
    const go = (p, d) => setTimeout(() => setPhase(p), d)
    const ts = [
      go("logo",   300),
      go("radar",  800),
      go("sub",    1400),
      go("line",   2000),
      go("ready",  2800),
      go("fade",   4200),
    ]
    const done = setTimeout(onComplete, 5000)
    return () => { ts.forEach(clearTimeout); clearTimeout(done) }
  }, [])

  useEffect(() => {
    if (phase === "black" || phase === "fade") {
      cancelAnimationFrame(rafRef.current)
      return
    }
    t0Ref.current = t0Ref.current || performance.now()
    const tick = (now) => {
      const deg = ((now - t0Ref.current) * 0.09) % 360
      setSweep(deg)
      RADAR_NODES.forEach((n, i) => {
        const diff = (deg - n.a + 360) % 360
        if (diff < 6) setActiveNodes(p => p.includes(i) ? p : [...p, i])
      })
      rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [phase])

  const v = (...ps) => ps.includes(phase)

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 50,
      background: "#04070a",
      display: "flex", alignItems: "center", justifyContent: "center",
      opacity: phase === "fade" ? 0 : 1,
      transition: "opacity 0.9s ease",
      overflow: "hidden",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Mono:wght@300&display=swap');
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(14px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes fadeIn  { from { opacity: 0; } to { opacity: 1; } }
        @keyframes growX   { from { transform: scaleX(0); } to { transform: scaleX(1); } }
        @keyframes radarIn { from { opacity: 0; transform: scale(0.88); } to { opacity: 1; transform: scale(1); } }
      `}</style>

      {/* Dot grid */}
      {v("logo","radar","sub","line","ready") && (
        <div style={{
          position: "absolute", inset: 0, pointerEvents: "none",
          backgroundImage: "radial-gradient(circle, #00a0e910 1px, transparent 1px)",
          backgroundSize: "36px 36px",
          animation: "fadeIn 1s ease both",
        }} />
      )}

      {/* Vignette */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        background: "radial-gradient(ellipse at center, transparent 35%, #04070a 100%)",
      }} />

      {/* Layout */}
      <div style={{
        display: "flex", alignItems: "center",
        gap: "80px", position: "relative", zIndex: 2,
      }}>

        {/* Radar */}
        {v("radar","sub","line","ready","fade") && (
          <div style={{ animation: "radarIn 0.6s cubic-bezier(0.16,1,0.3,1) both" }}>
            <RadarCanvas sweep={sweep} nodes={activeNodes} />
          </div>
        )}

        {/* Text */}
        <div style={{ display: "flex", flexDirection: "column" }}>

          {/* NOKIA */}
          {v("logo","radar","sub","line","ready","fade") && (
            <div style={{
              fontFamily: "'Syne', sans-serif",
              fontWeight: 800,
              fontSize: "88px",
              letterSpacing: "0.2em",
              color: "#ffffff",
              lineHeight: 1,
              animation: "fadeUp 0.7s cubic-bezier(0.16,1,0.3,1) both",
            }}>
              NOKIA
            </div>
          )}

          {/* Subtitle */}
          {v("sub","line","ready","fade") && (
            <div style={{
              fontFamily: "'DM Mono', monospace",
              fontWeight: 300,
              fontSize: "10px",
              letterSpacing: "0.3em",
              color: "#00a0e9",
              marginTop: "8px",
              textTransform: "uppercase",
              animation: "fadeUp 0.5s 0.1s ease both",
            }}>
              KubeShield — Attack Path Visualizer
            </div>
          )}

          {/* Divider */}
          {v("line","ready","fade") && (
            <div style={{
              height: "1px",
              background: "linear-gradient(90deg, #00a0e950, transparent)",
              margin: "24px 0",
              transformOrigin: "left",
              animation: "growX 0.8s cubic-bezier(0.16,1,0.3,1) both",
            }} />
          )}

          {/* Ready */}
          {v("ready","fade") && (
            <div style={{
              fontFamily: "'DM Mono', monospace",
              fontWeight: 300,
              fontSize: "10px",
              letterSpacing: "0.3em",
              color: "#22c55e",
              textTransform: "uppercase",
              animation: "fadeIn 0.5s ease both",
              display: "flex", alignItems: "center", gap: "10px",
            }}>
              <div style={{
                width: "6px", height: "6px",
                borderRadius: "50%",
                background: "#22c55e",
              }} />
              Secure Analysis Ready
            </div>
          )}
        </div>
      </div>

      {/* Bottom line */}
      {v("sub","line","ready","fade") && (
        <div style={{
          position: "absolute", bottom: 0, left: 0, right: 0,
          height: "1px",
          background: "linear-gradient(90deg, transparent, #00a0e925, transparent)",
          animation: "fadeIn 1s ease both",
        }} />
      )}
    </div>
  )
}

function RadarCanvas({ sweep, nodes }) {
  const S  = 210
  const cx = S / 2
  const cy = S / 2
  const R  = S / 2 - 14

  const xy = (angleDeg, frac) => {
    const rad = (angleDeg - 90) * (Math.PI / 180)
    return {
      x: cx + Math.cos(rad) * R * frac,
      y: cy + Math.sin(rad) * R * frac,
    }
  }

  const sweepRad = (sweep - 90) * (Math.PI / 180)

  return (
    <svg width={S} height={S} viewBox={`0 0 ${S} ${S}`}>

      {/* Rings */}
      {[1, 0.66, 0.33].map((f, i) => (
        <circle key={i} cx={cx} cy={cy} r={R * f}
          fill="none" stroke="#00a0e9"
          strokeWidth={i === 0 ? "0.8" : "0.4"}
          opacity={i === 0 ? 0.18 : 0.08}
        />
      ))}

      {/* Axis */}
      {[0, 45, 90, 135].map(a => {
        const rad = (a - 90) * Math.PI / 180
        return (
          <line key={a}
            x1={cx + Math.cos(rad) * R} y1={cy + Math.sin(rad) * R}
            x2={cx - Math.cos(rad) * R} y2={cy - Math.sin(rad) * R}
            stroke="#00a0e9" strokeWidth="0.3" opacity="0.07"
          />
        )
      })}

      {/* Sweep trail */}
      {Array.from({ length: 28 }).map((_, i) => {
        const ta  = sweep - i * 3
        const tr  = (ta - 90) * Math.PI / 180
        return (
          <line key={i}
            x1={cx} y1={cy}
            x2={cx + Math.cos(tr) * R}
            y2={cy + Math.sin(tr) * R}
            stroke="#00a0e9" strokeWidth="1.5"
            opacity={(1 - i / 28) * 0.18}
          />
        )
      })}

      {/* Sweep line */}
      <line
        x1={cx} y1={cy}
        x2={cx + Math.cos(sweepRad) * R}
        y2={cy + Math.sin(sweepRad) * R}
        stroke="#00a0e9" strokeWidth="1.2" opacity="0.75"
      />

      {/* Edges */}
      {nodes.map((i) =>
        nodes.map((j) => {
          if (j >= i) return null
          const a = xy(RADAR_NODES[i].a, RADAR_NODES[i].r)
          const b = xy(RADAR_NODES[j].a, RADAR_NODES[j].r)
          if (Math.hypot(a.x - b.x, a.y - b.y) > 75) return null
          return (
            <line key={`${i}-${j}`}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke="#ffffff" strokeWidth="0.4"
              opacity="0.1" strokeDasharray="3 4"
            />
          )
        })
      )}

      {/* Nodes */}
      {RADAR_NODES.map((n, i) => {
        if (!nodes.includes(i)) return null
        const { x, y } = xy(n.a, n.r)
        return (
          <g key={i}>
            <circle cx={x} cy={y} r={5}
              fill={n.c + "20"} stroke={n.c} strokeWidth="0.8"
            />
            <circle cx={x} cy={y} r={2.5} fill={n.c} opacity="0.9" />
          </g>
        )
      })}

      {/* Center */}
      <circle cx={cx} cy={cy} r={3} fill="#00a0e9" opacity="0.85" />
      <circle cx={cx} cy={cy} r={7} fill="none" stroke="#00a0e9" strokeWidth="0.4" opacity="0.25" />
    </svg>
  )
}
