import { useEffect, useRef } from "react"
import * as d3 from "d3"

const NODE_COLORS = {
  pod:            "#00a0e9",
  service:        "#a855f7",
  secret:         "#f97316",
  rbac:           "#ef4444",
  serviceaccount: "#eab308",
  networkpolicy:  "#22c55e",
  other:          "#6b7280",
}

const NODE_ICONS = {
  pod:            "⬡",
  service:        "◈",
  secret:         "🔑",
  rbac:           "🛡",
  serviceaccount: "👤",
  networkpolicy:  "🔒",
  other:          "●",
}

function getBlastRadius(nodes, edges, originId, hops = 2) {
  const adjacency = {}
  nodes.forEach(n => adjacency[n.id] = [])
  edges.forEach(e => {
    if (adjacency[e.source] !== undefined) adjacency[e.source].push(e.target)
    if (adjacency[e.target] !== undefined) adjacency[e.target].push(e.source)
  })

  const visited = { [originId]: 0 }
  const queue   = [[originId, 0]]
  const reachable = new Set()

  while (queue.length > 0) {
    const [current, depth] = queue.shift()
    if (depth >= hops) continue
    for (const neighbor of (adjacency[current] || [])) {
      if (!(neighbor in visited)) {
        visited[neighbor] = depth + 1
        reachable.add(neighbor)
        queue.push([neighbor, depth + 1])
      }
    }
  }

  return reachable
}

export default function GraphCanvas({
  nodes,
  edges,
  attackPath,
  onNodeClick,
  selectedNode,
  graphData,
}) {
  const svgRef = useRef()

  useEffect(() => {
    if (!nodes || nodes.length === 0) return

    const width  = svgRef.current.clientWidth
    const height = svgRef.current.clientHeight

    d3.select(svgRef.current).selectAll("*").remove()

    const svg = d3.select(svgRef.current)
      .attr("width",  width)
      .attr("height", height)

    // Defs
    const defs = svg.append("defs")

    const glowFilter = defs.append("filter").attr("id", "glow")
    glowFilter.append("feGaussianBlur").attr("stdDeviation", "4").attr("result", "coloredBlur")
    const feMerge = glowFilter.append("feMerge")
    feMerge.append("feMergeNode").attr("in", "coloredBlur")
    feMerge.append("feMergeNode").attr("in", "SourceGraphic")

    const redGlow = defs.append("filter").attr("id", "redglow")
    redGlow.append("feGaussianBlur").attr("stdDeviation", "6").attr("result", "coloredBlur")
    const feMerge2 = redGlow.append("feMerge")
    feMerge2.append("feMergeNode").attr("in", "coloredBlur")
    feMerge2.append("feMergeNode").attr("in", "SourceGraphic")

    const orangeGlow = defs.append("filter").attr("id", "orangeglow")
    orangeGlow.append("feGaussianBlur").attr("stdDeviation", "5").attr("result", "coloredBlur")
    const feMerge3 = orangeGlow.append("feMerge")
    feMerge3.append("feMergeNode").attr("in", "coloredBlur")
    feMerge3.append("feMergeNode").attr("in", "SourceGraphic")

    // Background grid
    const pattern = defs.append("pattern")
      .attr("id", "grid").attr("width", 40).attr("height", 40)
      .attr("patternUnits", "userSpaceOnUse")
    pattern.append("path")
      .attr("d", "M 40 0 L 0 0 0 40")
      .attr("fill", "none").attr("stroke", "#ffffff08").attr("strokeWidth", 1)
    svg.append("rect").attr("width", width).attr("height", height).attr("fill", "url(#grid)")

    const attackSet   = new Set(attackPath)
    const blastSet    = selectedNode
      ? getBlastRadius(nodes, edges, selectedNode.id, 2)
      : new Set()

    const links = edges.map(e => ({
      source: e.source,
      target: e.target,
      weight: e.weight,
    }))

    const simulation = d3.forceSimulation(nodes)
      .force("link",      d3.forceLink(links).id(d => d.id).distance(130))
      .force("charge",    d3.forceManyBody().strength(-320))
      .force("center",    d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(52))

    // Edges
    const link = svg.append("g").selectAll("line")
      .data(links).join("line")
      .attr("stroke", d => {
        const s = typeof d.source === "object" ? d.source.id : d.source
        const t = typeof d.target === "object" ? d.target.id : d.target
        if (attackSet.has(s) && attackSet.has(t)) return "#ef4444"
        if (blastSet.has(s) || blastSet.has(t))   return "#f9731660"
        return "#ffffff15"
      })
      .attr("stroke-width", d => {
        const s = typeof d.source === "object" ? d.source.id : d.source
        const t = typeof d.target === "object" ? d.target.id : d.target
        if (attackSet.has(s) && attackSet.has(t)) return 2.5
        if (blastSet.has(s) || blastSet.has(t))   return 1.5
        return 1
      })
      .attr("stroke-dasharray", d => {
        const s = typeof d.source === "object" ? d.source.id : d.source
        const t = typeof d.target === "object" ? d.target.id : d.target
        if (blastSet.has(s) || blastSet.has(t)) return "4,3"
        return null
      })
      .attr("filter", d => {
        const s = typeof d.source === "object" ? d.source.id : d.source
        const t = typeof d.target === "object" ? d.target.id : d.target
        if (attackSet.has(s) && attackSet.has(t)) return "url(#redglow)"
        return null
      })

    // Nodes
    const node = svg.append("g").selectAll("g")
      .data(nodes).join("g")
      .attr("cursor", "pointer")
      .call(
        d3.drag()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x; d.fy = d.y
          })
          .on("drag",  (event, d) => { d.fx = event.x; d.fy = event.y })
          .on("end",   (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null; d.fy = null
          })
      )
      .on("click", (event, d) => {
        event.stopPropagation()
        onNodeClick(d)
      })

    // Blast radius outer pulse ring
    node.filter(d => blastSet.has(d.id))
      .append("circle")
      .attr("r", 34)
      .attr("fill",   "none")
      .attr("stroke", "#f97316")
      .attr("stroke-width", 1)
      .attr("opacity", 0.3)
      .attr("stroke-dasharray", "4,3")

    // Selected node highlight
    node.filter(d => selectedNode && d.id === selectedNode.id)
      .append("circle")
      .attr("r", 30)
      .attr("fill",   "none")
      .attr("stroke", "#ffffff")
      .attr("stroke-width", 1.5)
      .attr("opacity", 0.4)
      .attr("filter", "url(#glow)")

    // Attack path outer ring
    node.append("circle")
      .attr("r", 28)
      .attr("fill",   "none")
      .attr("stroke", d => attackSet.has(d.id) ? "#ef4444" : "transparent")
      .attr("stroke-width", 2)
      .attr("filter",  d => attackSet.has(d.id) ? "url(#redglow)" : null)
      .attr("opacity", 0.6)

    // Main circle
    node.append("circle")
      .attr("r", 22)
      .attr("fill", d => {
        if (selectedNode && d.id === selectedNode.id) return `${NODE_COLORS[d.type] || NODE_COLORS.other}40`
        if (blastSet.has(d.id)) return "#f9731618"
        return `${NODE_COLORS[d.type] || NODE_COLORS.other}22`
      })
      .attr("stroke", d => {
        if (attackSet.has(d.id)) return "#ef4444"
        if (blastSet.has(d.id)) return "#f97316"
        return NODE_COLORS[d.type] || NODE_COLORS.other
      })
      .attr("stroke-width", d => {
        if (attackSet.has(d.id)) return 2.5
        if (blastSet.has(d.id)) return 2
        return 1.5
      })
      .attr("filter", "url(#glow)")

    // Icon
    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .attr("font-size", "14")
      .text(d => NODE_ICONS[d.type] || "●")

    // Label
    node.append("text")
      .attr("text-anchor", "middle")
      .attr("y", 34)
      .attr("font-size", "9")
      .attr("fill", "#ffffff80")
      .attr("font-family", "monospace")
      .text(d => d.name.length > 14 ? d.name.slice(0, 14) + "…" : d.name)

    // Risk badge
    node.filter(d => d.risk > 0)
      .append("circle")
      .attr("cx", 16).attr("cy", -16).attr("r", 8)
      .attr("fill", d => d.risk >= 70 ? "#ef4444"
                        : d.risk >= 40 ? "#f97316"
                        : d.risk >= 20 ? "#eab308"
                        : "#22c55e")

    node.filter(d => d.risk > 0)
      .append("text")
      .attr("x", 16).attr("y", -16)
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .attr("font-size", "7")
      .attr("font-weight", "bold")
      .attr("fill", "white")
      .text(d => d.risk)

    // Blast radius label
    node.filter(d => blastSet.has(d.id))
      .append("text")
      .attr("x", -16).attr("y", -16)
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .attr("font-size", "9")
      .text("💥")

    // Attack path animation
    if (attackPath.length > 1) {
      animateAttackPath(svg, nodes, attackPath, width, height)
    }

    simulation.on("tick", () => {
      link
        .attr("x1", d => d.source.x).attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x).attr("y2", d => d.target.y)
      node.attr("transform", d => `translate(${d.x},${d.y})`)
    })

    return () => simulation.stop()
  }, [nodes, edges, attackPath, selectedNode])

  return (
    <div className="relative w-full h-full">
      <svg
        ref={svgRef}
        className="w-full h-full"
        style={{ background: "transparent" }}
      />

      {/* Node Legend */}
      <div
        className="absolute top-3 right-3 flex flex-col gap-1.5 px-3 py-2.5 rounded"
        style={{
          background:    "#0a0a0acc",
          border:        "1px solid #ffffff10",
          backdropFilter:"blur(8px)",
        }}
      >
        <div className="text-[9px] text-white/30 tracking-widest uppercase mb-1">
          Node Types
        </div>
        {[
          { type: "pod",            label: "Pod / Container",  color: "#00a0e9", icon: "⬡" },
          { type: "service",        label: "Service / Ingress", color: "#a855f7", icon: "◈" },
          { type: "secret",         label: "Secret",            color: "#f97316", icon: "🔑" },
          { type: "rbac",           label: "RBAC Binding",      color: "#ef4444", icon: "🛡" },
          { type: "serviceaccount", label: "Service Account",   color: "#eab308", icon: "👤" },
          { type: "networkpolicy",  label: "Network Policy",    color: "#22c55e", icon: "🔒" },
        ].map(item => (
          <div key={item.type} className="flex items-center gap-2">
            <div
              className="w-4 h-4 rounded-full flex items-center justify-center text-[9px]"
              style={{ background: `${item.color}20`, border: `1px solid ${item.color}60` }}
            >
              {item.icon}
            </div>
            <span className="text-[10px] text-white/50">{item.label}</span>
          </div>
        ))}

        <div className="border-t border-white/10 mt-1 pt-1.5 flex flex-col gap-1.5">
          <div className="text-[9px] text-white/30 tracking-widest uppercase mb-0.5">
            Overlays
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full flex items-center justify-center"
              style={{ background: "#ef444420", border: "1px solid #ef4444" }}>
              <div className="w-1.5 h-1.5 rounded-full bg-[#ef4444]" />
            </div>
            <span className="text-[10px] text-white/50">Attack path</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-4 h-4 rounded-full flex items-center justify-center text-[9px]"
              style={{ border: "1px dashed #f97316", color: "#f97316" }}>
              💥
            </div>
            <span className="text-[10px] text-white/50">Blast radius</span>
          </div>
        </div>

        <div className="border-t border-white/10 mt-1 pt-1.5 flex flex-col gap-1.5">
          <div className="text-[9px] text-white/30 tracking-widest uppercase mb-0.5">
            Risk Badge
          </div>
          {[
            { label: "Critical", color: "#ef4444", range: "70+" },
            { label: "High",     color: "#f97316", range: "40+" },
            { label: "Medium",   color: "#eab308", range: "20+" },
            { label: "Low",      color: "#22c55e", range: "1+"  },
          ].map(item => (
            <div key={item.label} className="flex items-center gap-2">
              <div
                className="w-4 h-4 rounded-full flex items-center justify-center text-[8px] font-bold"
                style={{ background: item.color, color: "white" }}
              >
                {item.range.replace("+", "")}
              </div>
              <span className="text-[10px] text-white/50">
                {item.label} ({item.range})
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function animateAttackPath(svg, nodes, attackPath, width, height) {
  const nodeMap    = Object.fromEntries(nodes.map(n => [n.id, n]))
  const pathPoints = attackPath.map(id => nodeMap[id]).filter(Boolean)
  if (pathPoints.length < 2) return

  const dot = svg.append("circle")
    .attr("r", 6)
    .attr("fill",   "#ef4444")
    .attr("filter", "url(#redglow)")
    .attr("opacity", 0)

  function animateStep(index) {
    if (index >= pathPoints.length - 1) {
      setTimeout(() => animateStep(0), 1000)
      return
    }
    const from = pathPoints[index]
    const to   = pathPoints[index + 1]
    dot
      .attr("cx", from.x || width / 2)
      .attr("cy", from.y || height / 2)
      .attr("opacity", 1)
      .transition().duration(800).ease(d3.easeLinear)
      .attr("cx", to.x || width / 2)
      .attr("cy", to.y || height / 2)
      .on("end", () => animateStep(index + 1))
  }

  setTimeout(() => animateStep(0), 500)
}