import { useEffect, useState, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  ArrowLeft, Download, RefreshCw, AlertTriangle, Shield, Clock,
  Globe, Zap, CheckCircle2, XCircle, Loader2, Filter
} from 'lucide-react'
import { scanApi, reportApi, createScanWebSocket } from '../api/client'
import type { Scan, Vulnerability, ScanLogEntry, WsMessage } from '../types'
import VulnerabilityCard from '../components/VulnerabilityCard'
import RiskScore from '../components/RiskScore'
import SeverityBadge from '../components/SeverityBadge'
import { formatDistanceToNow, format } from 'date-fns'
import clsx from 'clsx'

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'

function StatusIcon({ status }: { status: Scan['status'] }) {
  if (status === 'running') return <Loader2 className="w-4 h-4 text-brand-400 animate-spin" />
  if (status === 'completed') return <CheckCircle2 className="w-4 h-4 text-green-400" />
  if (status === 'failed') return <XCircle className="w-4 h-4 text-red-400" />
  return <Clock className="w-4 h-4 text-yellow-400" />
}

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>()
  const [scan, setScan] = useState<Scan | null>(null)
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [log, setLog] = useState<ScanLogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<SeverityFilter>('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const wsRef = useRef<WebSocket | null>(null)

  const fetchVulns = async (scanId: string) => {
    const data = await scanApi.getVulnerabilities(scanId)
    setVulns(data.vulnerabilities)
  }

  const fetchLog = async (scanId: string) => {
    const data = await scanApi.getLog(scanId)
    setLog(data.log || [])
  }

  useEffect(() => {
    if (!id) return

    const init = async () => {
      try {
        const data = await scanApi.get(id)
        setScan(data)
        if (data.status === 'completed') {
          await fetchVulns(id)
        }
        await fetchLog(id)
      } finally {
        setLoading(false)
      }
    }
    init()

    wsRef.current = createScanWebSocket(id, (msg) => {
      const m = msg as WsMessage
      setScan(prev => prev ? {
        ...prev,
        status: m.status,
        progress: m.progress,
        total_vulnerabilities: m.total_vulnerabilities,
        critical_count: m.critical_count,
        high_count: m.high_count,
        medium_count: m.medium_count,
        low_count: m.low_count,
      } : prev)
      setLog(m.log || [])

      if (m.status === 'completed') {
        fetchVulns(id)
        scanApi.get(id).then(setScan)
      }
    })

    return () => {
      wsRef.current?.close()
    }
  }, [id])

  const filtered = vulns.filter(v => {
    const sevOk = filter === 'all' || v.severity === filter
    const catOk = categoryFilter === 'all' || v.category === categoryFilter
    return sevOk && catOk
  })

  const categories = ['all', ...Array.from(new Set(vulns.map(v => v.category)))]

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 text-brand-400 animate-spin" />
      </div>
    )
  }

  if (!scan) {
    return (
      <div className="p-8 text-center">
        <p className="text-slate-400">Scan not found.</p>
        <Link to="/" className="text-brand-400 hover:text-brand-300 text-sm mt-2 inline-block">← Back to dashboard</Link>
      </div>
    )
  }

  const duration = scan.started_at && scan.completed_at
    ? Math.round((new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime()) / 1000)
    : null

  return (
    <div className="p-8 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-start gap-4">
          <Link to="/" className="mt-1 p-2 rounded-xl hover:bg-bg-elevated transition-colors text-slate-400 hover:text-white">
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <StatusIcon status={scan.status} />
              <span className={clsx(
                'text-xs font-semibold uppercase tracking-wider',
                scan.status === 'completed' ? 'text-green-400' :
                scan.status === 'running' ? 'text-brand-400' :
                scan.status === 'failed' ? 'text-red-400' : 'text-yellow-400'
              )}>
                {scan.status}
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white">{scan.name || scan.target_url}</h1>
            <p className="text-slate-400 text-sm mt-0.5 font-mono">{scan.target_url}</p>
          </div>
        </div>

        {scan.status === 'completed' && id && (
          <div className="flex gap-2">
            <button
              onClick={() => reportApi.downloadMarkdown(id)}
              className="btn-ghost text-sm"
            >
              <Download className="w-4 h-4" />
              Export MD
            </button>
          </div>
        )}
      </div>

      {/* Progress bar (running) */}
      {scan.status === 'running' && (
        <div className="card p-5 mb-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Loader2 className="w-4 h-4 text-brand-400 animate-spin" />
              <span className="text-sm font-semibold text-white">Scanning in progress...</span>
            </div>
            <span className="text-sm font-bold text-brand-400">{scan.progress}%</span>
          </div>
          <div className="h-2 bg-bg-border rounded-full overflow-hidden mb-4">
            <div
              className="h-full bg-gradient-to-r from-brand-600 to-brand-400 rounded-full transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          {log.length > 0 && (
            <div className="space-y-1">
              {log.slice(-4).map((entry, i) => (
                <div key={i} className="flex items-center gap-2.5 text-xs">
                  {entry.status === 'done'
                    ? <CheckCircle2 className="w-3 h-3 text-green-400 shrink-0" />
                    : entry.status === 'running'
                    ? <Loader2 className="w-3 h-3 text-brand-400 animate-spin shrink-0" />
                    : <XCircle className="w-3 h-3 text-red-400 shrink-0" />
                  }
                  <span className={clsx(
                    entry.status === 'done' ? 'text-slate-400' : 'text-white'
                  )}>
                    {entry.message}
                    {entry.found !== undefined && entry.found > 0 && (
                      <span className="text-orange-400 ml-1">({entry.found} found)</span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Summary cards */}
      {scan.status === 'completed' && (
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
          <div className="card p-5 flex flex-col items-center justify-center lg:col-span-1">
            <RiskScore score={scan.risk_score} />
          </div>

          {([
            ['Critical', scan.critical_count, 'text-red-400 bg-red-500/10 border-red-500/15'],
            ['High', scan.high_count, 'text-orange-400 bg-orange-500/10 border-orange-500/15'],
            ['Medium', scan.medium_count, 'text-yellow-400 bg-yellow-500/10 border-yellow-500/15'],
            ['Low', scan.low_count, 'text-green-400 bg-green-500/10 border-green-500/15'],
          ] as const).map(([label, count, cls]) => (
            <div key={label} className="card p-5">
              <p className={clsx('text-3xl font-bold', cls.split(' ')[0])}>{count}</p>
              <p className="text-xs text-slate-500 mt-1">{label}</p>
              <button
                onClick={() => setFilter(f => f === label.toLowerCase() as SeverityFilter ? 'all' : label.toLowerCase() as SeverityFilter)}
                className={clsx(
                  'mt-2 text-xs px-2 py-0.5 rounded-lg border transition-colors',
                  filter === label.toLowerCase() ? cls : 'text-slate-500 border-transparent hover:border-bg-border'
                )}
              >
                {filter === label.toLowerCase() ? 'Clear' : 'Filter'}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Meta */}
      <div className="grid grid-cols-3 gap-3 mb-6">
        {[
          { icon: Globe, label: 'Endpoints Tested', value: scan.endpoints_tested },
          { icon: Zap, label: 'Requests Made', value: scan.requests_made },
          { icon: Clock, label: 'Duration', value: duration ? `${duration}s` : '—' },
        ].map(({ icon: Icon, label, value }) => (
          <div key={label} className="card px-4 py-3 flex items-center gap-3">
            <Icon className="w-4 h-4 text-slate-500 shrink-0" />
            <div>
              <p className="text-xs text-slate-500">{label}</p>
              <p className="text-sm font-semibold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Vulnerabilities */}
      {scan.status === 'completed' && (
        <div>
          <div className="flex flex-wrap items-center gap-3 mb-4">
            <h2 className="text-lg font-semibold text-white">
              Vulnerabilities
              <span className="text-slate-500 text-sm font-normal ml-2">({filtered.length})</span>
            </h2>

            <div className="flex-1" />

            <div className="flex items-center gap-1 bg-bg-card border border-bg-border rounded-xl p-1">
              {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(s => (
                <button
                  key={s}
                  onClick={() => setFilter(s)}
                  className={clsx(
                    'px-3 py-1.5 rounded-lg text-xs font-medium transition-colors capitalize',
                    filter === s ? 'bg-brand-500/20 text-brand-400' : 'text-slate-500 hover:text-white'
                  )}
                >
                  {s}
                </button>
              ))}
            </div>

            {categories.length > 2 && (
              <select
                value={categoryFilter}
                onChange={e => setCategoryFilter(e.target.value)}
                className="input w-auto py-2 text-xs"
              >
                {categories.map(c => (
                  <option key={c} value={c}>{c === 'all' ? 'All categories' : c}</option>
                ))}
              </select>
            )}
          </div>

          {filtered.length === 0 ? (
            <div className="card p-12 flex flex-col items-center text-center">
              <Shield className="w-12 h-12 text-green-400 mb-4" />
              <p className="text-white font-semibold mb-1">
                {vulns.length === 0 ? 'No vulnerabilities found' : 'No results for this filter'}
              </p>
              <p className="text-sm text-slate-500">
                {vulns.length === 0
                  ? 'The API passed all security checks in the selected modules.'
                  : 'Try adjusting the severity or category filter.'}
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {filtered
                .sort((a, b) => {
                  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
                  return (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
                })
                .map((v, i) => (
                  <VulnerabilityCard key={v.id} vuln={v} index={i} />
                ))}
            </div>
          )}
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="card p-8 flex flex-col items-center text-center">
          <XCircle className="w-12 h-12 text-red-400 mb-4" />
          <p className="text-white font-semibold mb-1">Scan Failed</p>
          <p className="text-sm text-slate-500 max-w-md">{scan.error_message || 'An unexpected error occurred during the scan.'}</p>
        </div>
      )}
    </div>
  )
}
