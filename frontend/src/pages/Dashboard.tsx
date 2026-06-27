import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, AlertTriangle, Zap, Clock, TrendingUp, Plus, ChevronRight, Activity } from 'lucide-react'
import { scanApi } from '../api/client'
import type { Scan, ScanStats } from '../types'
import { formatDistanceToNow } from 'date-fns'
import clsx from 'clsx'
import { RadialBarChart, RadialBar, ResponsiveContainer, Tooltip } from 'recharts'

function StatusDot({ status }: { status: Scan['status'] }) {
  const colors: Record<string, string> = {
    completed: 'bg-green-400',
    running: 'bg-brand-400 animate-pulse',
    pending: 'bg-yellow-400',
    failed: 'bg-red-400',
  }
  return <span className={clsx('w-2 h-2 rounded-full inline-block', colors[status] ?? 'bg-slate-500')} />
}

function ScanRow({ scan }: { scan: Scan }) {
  const ago = scan.created_at
    ? formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })
    : '—'
  return (
    <Link
      to={`/scan/${scan.id}`}
      className="flex items-center gap-4 px-5 py-3.5 hover:bg-bg-elevated rounded-xl transition-colors group"
    >
      <StatusDot status={scan.status} />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white truncate">{scan.name || scan.target_url}</p>
        <p className="text-xs text-slate-500 truncate">{scan.target_url}</p>
      </div>
      {scan.status === 'completed' && (
        <div className="flex items-center gap-3 shrink-0">
          {scan.critical_count > 0 && (
            <span className="badge-critical">{scan.critical_count} crit</span>
          )}
          {scan.high_count > 0 && (
            <span className="badge-high">{scan.high_count} high</span>
          )}
          <span className="text-xs text-slate-500">
            Score: <span className="text-white font-semibold">{scan.risk_score.toFixed(1)}</span>
          </span>
        </div>
      )}
      {scan.status === 'running' && (
        <div className="flex items-center gap-2">
          <div className="w-24 h-1.5 bg-bg-border rounded-full overflow-hidden">
            <div
              className="h-full bg-brand-500 rounded-full transition-all"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
          <span className="text-xs text-slate-500">{scan.progress}%</span>
        </div>
      )}
      <span className="text-xs text-slate-600">{ago}</span>
      <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors" />
    </Link>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState<ScanStats | null>(null)
  const [scans, setScans] = useState<Scan[]>([])
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const [statsData, scansData] = await Promise.all([
        scanApi.stats(),
        scanApi.list(0, 20),
      ])
      setStats(statsData)
      setScans(scansData.scans)
    } catch {
      // backend not yet running
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  const hour = new Date().getHours()
  const greeting = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening'

  const severityChart = stats
    ? [
        { name: 'Critical', value: stats.critical_total, fill: '#ef4444' },
        { name: 'High', value: stats.high_total, fill: '#f97316' },
        { name: 'Medium', value: stats.medium_total, fill: '#eab308' },
      ]
    : []

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="mb-8 flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">
            {greeting} — let's audit your APIs.
          </h1>
          <p className="text-slate-400 mt-1">
            {stats
              ? `${stats.total_scans} scans run · ${stats.total_vulnerabilities} vulnerabilities found`
              : 'Loading overview...'}
          </p>
        </div>
        <Link to="/scan/new" className="btn-primary">
          <Plus className="w-4 h-4" />
          New Scan
        </Link>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[
          {
            label: 'Total Scans',
            value: stats?.total_scans ?? '—',
            icon: Activity,
            color: 'text-brand-400',
            bg: 'bg-brand-500/8',
          },
          {
            label: 'Critical Findings',
            value: stats?.critical_total ?? '—',
            icon: AlertTriangle,
            color: 'text-red-400',
            bg: 'bg-red-500/8',
          },
          {
            label: 'Avg Risk Score',
            value: stats ? stats.avg_risk_score.toFixed(1) : '—',
            icon: TrendingUp,
            color: 'text-orange-400',
            bg: 'bg-orange-500/8',
          },
          {
            label: 'Active Scans',
            value: stats?.running_scans ?? '—',
            icon: Zap,
            color: 'text-green-400',
            bg: 'bg-green-500/8',
          },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="card p-5">
            <div className="flex items-start justify-between mb-3">
              <div className={clsx('w-9 h-9 rounded-xl flex items-center justify-center', bg)}>
                <Icon className={clsx('w-4.5 h-4.5', color)} />
              </div>
            </div>
            <p className="text-2xl font-bold text-white">{value}</p>
            <p className="text-xs text-slate-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Recent scans */}
        <div className="lg:col-span-2 card">
          <div className="flex items-center justify-between px-5 py-4 border-b border-bg-border">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Clock className="w-4 h-4 text-slate-400" />
              Recent Scans
            </h2>
            <Link to="/reports" className="text-xs text-brand-400 hover:text-brand-300">
              View all
            </Link>
          </div>
          <div className="p-2">
            {loading ? (
              <div className="space-y-2 p-3">
                {[1, 2, 3].map(i => (
                  <div key={i} className="h-14 bg-bg-elevated rounded-xl animate-pulse" />
                ))}
              </div>
            ) : scans.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <div className="w-16 h-16 rounded-2xl bg-brand-500/10 border border-brand-500/15 flex items-center justify-center mb-4">
                  <Shield className="w-8 h-8 text-brand-400" />
                </div>
                <p className="text-white font-semibold mb-1">No scans yet</p>
                <p className="text-sm text-slate-500 mb-5">Run your first API security audit</p>
                <Link to="/scan/new" className="btn-primary text-sm">
                  <Plus className="w-4 h-4" />
                  Start Scanning
                </Link>
              </div>
            ) : (
              scans.map(scan => <ScanRow key={scan.id} scan={scan} />)
            )}
          </div>
        </div>

        {/* Severity overview */}
        <div className="card p-5 flex flex-col">
          <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-slate-400" />
            Severity Breakdown
          </h2>
          {stats && stats.total_vulnerabilities > 0 ? (
            <div className="flex-1 flex flex-col gap-3">
              {[
                { label: 'Critical', count: stats.critical_total, color: 'bg-red-500', max: stats.total_vulnerabilities },
                { label: 'High', count: stats.high_total, color: 'bg-orange-500', max: stats.total_vulnerabilities },
                { label: 'Medium', count: stats.medium_total, color: 'bg-yellow-500', max: stats.total_vulnerabilities },
              ].map(({ label, count, color, max }) => (
                <div key={label}>
                  <div className="flex justify-between text-xs mb-1.5">
                    <span className="text-slate-400">{label}</span>
                    <span className="text-white font-medium">{count}</span>
                  </div>
                  <div className="h-1.5 bg-bg-border rounded-full overflow-hidden">
                    <div
                      className={clsx('h-full rounded-full transition-all duration-700', color)}
                      style={{ width: `${max > 0 ? (count / max) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              ))}

              <div className="mt-4 pt-4 border-t border-bg-border">
                <p className="text-xs text-slate-500 mb-1">Average Risk Score</p>
                <p className="text-3xl font-bold text-white">
                  {stats.avg_risk_score.toFixed(1)}
                  <span className="text-base text-slate-500 font-normal"> / 10</span>
                </p>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-6">
              <Shield className="w-10 h-10 text-slate-700 mb-3" />
              <p className="text-sm text-slate-500">No vulnerabilities detected yet</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
