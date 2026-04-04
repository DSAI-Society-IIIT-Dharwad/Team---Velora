import { useState, useRef } from "react"
import axios from "axios"

export default function UploadPanel({ onComplete }) {
  const [status, setStatus] = useState("idle")
  // idle | uploading | success | error
  const [errorMsg, setErrorMsg] = useState("")
  const [fileName, setFileName] = useState("")
  const fileRef = useRef()

  const handleFile = async (file) => {
    if (!file) return

    const ext = file.name.split(".").pop().toLowerCase()
    if (!["yaml", "yml"].includes(ext)) {
      setErrorMsg("Only .yaml or .yml files accepted")
      setStatus("error")
      return
    }

    if (file.size > 500 * 1024) {
      setErrorMsg("File too large. Max 500KB.")
      setStatus("error")
      return
    }

    setFileName(file.name)
    setStatus("uploading")
    setErrorMsg("")

    const formData = new FormData()
    formData.append("file", file)

    try {
      const res = await axios.post("/api/analyze", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      })
      setStatus("success")
      onComplete(res.data)
    } catch (err) {
      setErrorMsg("Analysis failed. Is the backend running?")
      setStatus("error")
    }
  }

  const handleDrop = (e) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    handleFile(file)
  }

  const handleChange = (e) => {
    handleFile(e.target.files[0])
  }

  return (
    <div className="flex flex-col gap-3">
      {/* Title */}
      <div className="text-xs text-[#00a0e9] tracking-widest uppercase font-semibold">
        Upload Cluster Config
      </div>

      {/* Drop Zone */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        onClick={() => fileRef.current.click()}
        className="border border-dashed border-white/20 rounded-lg p-6 flex flex-col items-center gap-2 cursor-pointer hover:border-[#00a0e9] hover:bg-white/5 transition-all"
      >
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#00a0e9" strokeWidth="1.5">
          <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
          <polyline points="17 8 12 3 7 8" />
          <line x1="12" y1="3" x2="12" y2="15" />
        </svg>
        <span className="text-white/50 text-xs text-center">
          Drop your <span className="text-white">.yaml</span> file here
          <br />or click to browse
        </span>
        <input
          ref={fileRef}
          type="file"
          accept=".yaml,.yml"
          className="hidden"
          onChange={handleChange}
        />
      </div>

      {/* Status */}
      {status === "uploading" && (
        <div className="flex items-center gap-2 text-xs text-[#00a0e9]">
          <Spinner />
          Analyzing cluster...
        </div>
      )}

      {status === "success" && (
        <div className="text-xs text-green-400 flex items-center gap-2">
          <span>✓</span>
          <span className="truncate">{fileName} analyzed</span>
        </div>
      )}

      {status === "error" && (
        <div className="text-xs text-red-400">{errorMsg}</div>
      )}

      {/* Security badge */}
      <div className="flex items-center gap-2 mt-1 bg-white/5 rounded px-3 py-2">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#00a0e9" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
        <span className="text-white/40 text-[10px] leading-tight">
          Your file never leaves this server. No data stored.
        </span>
      </div>
    </div>
  )
}

function Spinner() {
  return (
    <svg className="animate-spin" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
    </svg>
  )
}