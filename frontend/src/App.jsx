import { useState } from "react"
import NokiaIntro from "./components/NokiaIntro"
import UploadPanel from "./components/UploadPanel"
import GraphCanvas from "./components/GraphCanvas"
import AISidebar from "./components/AISidebar"
import RiskScore from "./components/RiskScore"
import KillChain from "./components/KillChain"
import BlastRadius from "./components/BlastRadius"
import RBACChains from "./components/RBACChains"

export default function App() {
  const [introComplete, setIntroComplete]   = useState(false)
  const [graphData, setGraphData]           = useState(null)
  const [attackPath, setAttackPath]         = useState([])
  const [clusterRisk, setClusterRisk]       = useState(0)
  const [selectedNode, setSelectedNode]     = useState(null)
  const [rbacChains, setRbacChains]         = useState([])
  const [activeTab, setActiveTab]           = useState("graph")
  // activeTab: "graph" | "rbac"

  const handleAnalysisComplete = (data) => {
    setGraphData(data)
    setAttackPath(data.attack_path)
    setClusterRisk(data.cluster_risk)
    setRbacChains(data.rbac_chains || [])
  }

  const handleNodeClick = (node) => {
    setSelectedNode(node)
  }

  if (!introComplete) {
    return <NokiaIntro onComplete={() => setIntroComplete(true)} />
  }

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white flex flex-col">

      {/* Header */}
      <header className="border-b border-[#00a0e9] px-6 py-3 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <span className="text-[#00a0e9] font-black text-2xl tracking-widest"
            style={{ textShadow: "0 0 20px #00a0e980" }}>
            NOKIA
          </span>
          <span className="text-white/30">|</span>
          <span className="text-white font-semibold tracking-wide">KubeShield</span>
        </div>

        {/* Center tabs — only show after analysis */}
        {graphData && (
          <div className="flex items-center gap-1 bg-white/5 rounded-lg p-1">
            {[
              { id: "graph", label: "Attack Graph" },
              { id: "rbac",  label: "RBAC Chains"  },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className="px-4 py-1.5 rounded text-xs tracking-widest uppercase transition-all"
                style={{
                  background:  activeTab === tab.id ? "#00a0e9" : "transparent",
                  color:       activeTab === tab.id ? "white"   : "#ffffff60",
                  fontWeight:  activeTab === tab.id ? "bold"    : "normal",
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>
        )}

        <span className="text-xs text-white/40 tracking-widest uppercase">
          Kubernetes Attack Path Visualizer
        </span>
      </header>

      {/* Main Layout */}
      <div className="flex flex-1 overflow-hidden">

        {/* Left Panel */}
        <div className="w-72 border-r border-white/10 flex flex-col gap-4 p-4 overflow-y-auto shrink-0">
          <UploadPanel onComplete={handleAnalysisComplete} />
          {graphData && <RiskScore score={clusterRisk} />}
        </div>

        {/* Center */}
        <div className="flex-1 flex flex-col overflow-hidden">

          {activeTab === "graph" && (
            <>
              <div className="flex-1 relative">
                {graphData ? (
                  <GraphCanvas
                    nodes={graphData.nodes}
                    edges={graphData.edges}
                    attackPath={attackPath}
                    onNodeClick={handleNodeClick}
                    selectedNode={selectedNode}
                    graphData={graphData}
                  />
                ) : (
                  <div className="flex flex-col items-center justify-center h-full gap-4">
                    <div className="text-white/10 text-sm tracking-widest uppercase">
                      Upload a Kubernetes YAML to begin
                    </div>
                    <div className="text-white/5 text-xs tracking-widest">
                      Supports pods · services · secrets · rbac · serviceaccounts
                    </div>
                  </div>
                )}
              </div>

              {graphData && attackPath.length > 0 && (
                <KillChain
                  attackPath={attackPath}
                  nodes={graphData.nodes}
                  onNodeClick={handleNodeClick}
                />
              )}
            </>
          )}

          {activeTab === "rbac" && (
            <RBACChains chains={rbacChains} />
          )}
        </div>

        {/* Right Panel — AI + Blast Radius */}
        {selectedNode && (
          <div className="w-80 border-l border-white/10 flex flex-col overflow-hidden shrink-0">
            <AISidebar node={selectedNode} />
            {graphData && (
              <BlastRadius
                node={selectedNode}
                nodes={graphData.nodes}
                edges={graphData.edges}
              />
            )}
          </div>
        )}
      </div>
    </div>
  )
}