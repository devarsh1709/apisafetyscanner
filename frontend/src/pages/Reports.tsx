import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { FileText, Download, Trash2, ExternalLink, Shield, AlertTriangle, Clock } from 'lucide-react'
import { scanApi, reportApi } from '../api/client'
import type { Scan } from '../types'
import { format } from 'date-fns'
import clsx from 'clsx'

function RiskBadge({ score }: { score: number }) {
  const [label, color] =
    score >= 8 ? ['Critical', 'badge-critical'] :
    score >= 6 ? ['High', 'badge-high'] :
    score >= 4 ? ['Medium', 'badge-medium'] :
    score >= 2 ? ['Low', 'badge-low'] :
    ['Minimal', 'badge-info']
  return <span className={color}>{label} Risk</span>
}

export default function Reports() {
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)
  const [deleting, setDeleting] = useState<string | null>(null)

  const load = async () => {
    try {
      const { scans } = await scanApi.list(0, 100)
      setScans(scans.filter(s => s.status === 'completed'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this scan and all its results?')) return
    setDeleting(id)
    try {
      await scanApi.delete(id)
      setScans(prev => prev.filter(s => s.id !== id))
    } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="mb-8 flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Scan Reports</h1>
          <p className="text-slate-400 mt-1">{scans.length} completed scan{scans.length !== 1 ? 's' : ''}</p>
        </div>
        <Link to="/scan/new" className="btn-primary">
          <Shield className="w-4 h-4" />
          New Scan
        </Link>
      </div>

      {loading ? (
        <div className="space-y-3">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-28 card animate-pulse" />
          ))}
        </div>
      ) : scans.length === 0 ? (
        <div className="card p-16 flex flex-col items-center text-center">
          <div className="w-16 h-16 rounded-2xl bg-brand-500/10 border border-brand-500/15 flex items-center justify-center mb-4">
            <FileText className="w-8 h-8 text-brand-400" />
          </div>
          <p className="text-white font-semibold mb-2">No completed reports yet</p>
          <p className="text-sm text-slate-500 mb-6 max-w-sm">
            Start your first API security scan to generate a detailed vulnerability report.
          </p>
          <Link to="/scan/new" className="btn-primary">
            <Shield className="w-4 h-4" />
            Start Scanning
          </Link>
        </div>
      ) : (
        <div className="space-y-3">
          {scans.map(scan => (
            <div key={scan.id} className="card hover:shadow-glow transition-all duration-300 group">
              <div className="p-5 flex items-center gap-5">
                <div className={clsx(
                  'w-12 h-12 rounded-xl flex items-center justify-center shrink-0',
                  scan.critical_count > 0 ? 'bg-red-500/10' :
                  scan.high_count > 0 ? 'bg-orange-500/10' :
                  'bg-green-500/10'
                )}>
                  {scan.critical_count > 0 || scan.high_count > 0
                    ? <AlertTriangle className={clsx('w-5 h-5', scan.critical_count > 0 ? 'text-red-400' : 'text-orange-400')} />
                    : <Shield className="w-5 h-5 text-green-400" />
                  }
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-sm font-semibold text-white truncate">
                      {scan.name || scan.target_url}
                    </p>
                    <RiskBadge score={scan.risk_score} />
                  </div>
                  <p className="text-xs text-slate-500 font-mono truncate">{scan.target_url}</p>
                  <div className="flex items-center gap-4 mt-2">
                    {scan.critical_count > 0 && (
                      <span className="text-xs text-red-400">{scan.critical_count} critical</span>
                    )}
                    {scan.high_count > 0 && (
                      <span className="text-xs text-orange-400">{scan.high_count} high</span>
                    )}
                    {scan.medium_count > 0 && (
                      <span className="text-xs text-yellow-400">{scan.medium_count} medium</span>
                    )}
                    <span className="text-xs text-slate-600">
                      {scan.total_vulnerabilities} total findings
                    </span>
                    {scan.completed_at && (
                      <span className="text-xs text-slate-600 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {format(new Date(scan.completed_at), 'MMM d, yyyy HH:mm')}
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Link
                    to={`/scan/${scan.id}`}
                    className="p-2 rounded-xl hover:bg-bg-elevated text-slate-400 hover:text-white transition-colors"
                    title="View details"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </Link>
                  <button
                    onClick={() => reportApi.downloadMarkdown(scan.id)}
                    className="p-2 rounded-xl hover:bg-bg-elevated text-slate-400 hover:text-white transition-colors"
                    title="Download Markdown report"
                  >
                    <Download className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(scan.id)}
                    disabled={deleting === scan.id}
                    className="p-2 rounded-xl hover:bg-red-500/10 text-slate-400 hover:text-red-400 transition-colors"
                    title="Delete scan"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>

                <div className="text-right shrink-0 ml-2">
                  <p className="text-2xl font-bold text-white">{scan.risk_score.toFixed(1)}</p>
                  <p className="text-xs text-slate-500">risk score</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
