import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Plus, ChevronDown, ChevronUp, Info } from 'lucide-react'
import { scanApi } from '../api/client'
import clsx from 'clsx'

const SCAN_MODULES = [
  { id: 'authentication', label: 'Authentication & JWT', desc: 'Missing auth, weak JWT secrets, algorithm confusion, default credentials' },
  { id: 'rate_limiting', label: 'Rate Limiting', desc: 'Missing limits, bypass via headers/paths, response header analysis' },
  { id: 'injection', label: 'Injection Attacks', desc: 'SQL, NoSQL, SSTI, Command Injection, XSS, XXE' },
  { id: 'cors', label: 'CORS Misconfiguration', desc: 'Wildcard origins, reflected origins, null origin, subdomain trust' },
  { id: 'headers', label: 'Security Headers', desc: 'CSP, HSTS, X-Frame-Options, cookie flags, cache control' },
  { id: 'ssl', label: 'SSL / TLS', desc: 'Certificate validity, expiry, domain match, weak ciphers, HTTP redirect' },
  { id: 'info_disclosure', label: 'Information Disclosure', desc: 'Exposed .env, stack traces, secrets, PII, debug paths, git files' },
  { id: 'idor', label: 'IDOR & Access Control', desc: 'ID manipulation, path traversal, mass assignment, broken object auth' },
  { id: 'methods', label: 'HTTP Methods', desc: 'Dangerous methods (DELETE/PUT), method override headers, TRACE' },
]

export default function NewScan() {
  const nav = useNavigate()
  const [url, setUrl] = useState('')
  const [name, setName] = useState('')
  const [authToken, setAuthToken] = useState('')
  const [selectedModules, setSelectedModules] = useState<string[]>(SCAN_MODULES.map(m => m.id))
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [customHeaders, setCustomHeaders] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  const toggleModule = (id: string) => {
    setSelectedModules(prev =>
      prev.includes(id) ? prev.filter(m => m !== id) : [...prev, id]
    )
  }

  const selectAll = () => setSelectedModules(SCAN_MODULES.map(m => m.id))
  const selectNone = () => setSelectedModules([])

  const parseHeaders = (): Record<string, string> => {
    const result: Record<string, string> = {}
    customHeaders.split('\n').forEach(line => {
      const [k, ...v] = line.split(':')
      if (k && v.length) result[k.trim()] = v.join(':').trim()
    })
    return result
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) { setError('Target URL is required'); return }
    if (selectedModules.length === 0) { setError('Select at least one scan module'); return }
    setError('')
    setSubmitting(true)
    try {
      const scan = await scanApi.create({
        target_url: url.trim(),
        name: name.trim() || undefined,
        scan_types: selectedModules,
        auth_token: authToken.trim() || undefined,
        headers: Object.keys(parseHeaders()).length ? parseHeaders() : undefined,
      })
      nav(`/scan/${scan.id}`)
    } catch (err: unknown) {
      setError('Failed to start scan. Is the backend running?')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="p-8 max-w-3xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">New Security Scan</h1>
        <p className="text-slate-400 mt-1">Configure your API target and select which vulnerability classes to test.</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        {/* Target */}
        <div className="card p-6 space-y-4">
          <h2 className="text-sm font-semibold text-white">Target</h2>

          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Target URL <span className="text-red-400">*</span></label>
            <input
              className="input"
              placeholder="https://api.example.com/v1/users"
              value={url}
              onChange={e => setUrl(e.target.value)}
            />
            <p className="text-xs text-slate-600 mt-1.5">Full URL including path. Query parameters are used for injection tests.</p>
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Scan Name (optional)</label>
            <input
              className="input"
              placeholder="Production API audit — June 2026"
              value={name}
              onChange={e => setName(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1.5">Bearer Token (optional)</label>
            <input
              className="input font-mono text-sm"
              placeholder="eyJhbGciOiJSUzI1NiJ9..."
              value={authToken}
              onChange={e => setAuthToken(e.target.value)}
              type="password"
            />
            <p className="text-xs text-slate-600 mt-1.5">Used to test authenticated endpoints and JWT vulnerabilities.</p>
          </div>
        </div>

        {/* Advanced */}
        <div className="card overflow-hidden">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full px-6 py-4 flex items-center justify-between text-sm font-semibold text-white hover:bg-bg-elevated transition-colors"
          >
            <span>Advanced Options</span>
            {showAdvanced ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
          </button>

          {showAdvanced && (
            <div className="px-6 pb-6 border-t border-bg-border pt-4">
              <label className="block text-xs text-slate-400 mb-1.5">Custom Request Headers</label>
              <textarea
                className="input h-28 resize-none font-mono text-xs"
                placeholder={'X-Tenant-ID: abc123\nX-Custom-Header: value'}
                value={customHeaders}
                onChange={e => setCustomHeaders(e.target.value)}
              />
              <p className="text-xs text-slate-600 mt-1.5">One header per line in Key: Value format.</p>
            </div>
          )}
        </div>

        {/* Modules */}
        <div className="card p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white">Scan Modules</h2>
            <div className="flex gap-2">
              <button type="button" onClick={selectAll} className="text-xs text-brand-400 hover:text-brand-300">Select all</button>
              <span className="text-slate-600">·</span>
              <button type="button" onClick={selectNone} className="text-xs text-slate-400 hover:text-white">Clear</button>
            </div>
          </div>

          <div className="space-y-2">
            {SCAN_MODULES.map(mod => (
              <label
                key={mod.id}
                className={clsx(
                  'flex items-start gap-3 p-3.5 rounded-xl border cursor-pointer transition-all duration-150',
                  selectedModules.includes(mod.id)
                    ? 'border-brand-500/30 bg-brand-500/5'
                    : 'border-bg-border hover:border-bg-elevated hover:bg-bg-elevated/50'
                )}
              >
                <input
                  type="checkbox"
                  className="mt-0.5 accent-indigo-500 w-4 h-4"
                  checked={selectedModules.includes(mod.id)}
                  onChange={() => toggleModule(mod.id)}
                />
                <div>
                  <p className="text-sm font-medium text-white">{mod.label}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{mod.desc}</p>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Disclaimer */}
        <div className="flex items-start gap-3 px-4 py-3 rounded-xl bg-yellow-500/5 border border-yellow-500/10">
          <Info className="w-4 h-4 text-yellow-500 shrink-0 mt-0.5" />
          <p className="text-xs text-yellow-600">
            Only scan APIs you own or have explicit written permission to test. Unauthorized scanning may be illegal.
          </p>
        </div>

        {error && (
          <div className="px-4 py-3 rounded-xl bg-red-500/10 border border-red-500/20 text-sm text-red-400">
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={submitting}
          className="btn-primary w-full justify-center py-3 text-base"
        >
          {submitting ? (
            <>
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Starting scan...
            </>
          ) : (
            <>
              <Shield className="w-4.5 h-4.5" />
              Launch Security Scan
            </>
          )}
        </button>
      </form>
    </div>
  )
}
