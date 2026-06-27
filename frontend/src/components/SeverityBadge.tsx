import type { Severity } from '../types'

const CONFIG: Record<Severity, { label: string; className: string }> = {
  critical: { label: 'Critical', className: 'badge-critical' },
  high:     { label: 'High',     className: 'badge-high' },
  medium:   { label: 'Medium',   className: 'badge-medium' },
  low:      { label: 'Low',      className: 'badge-low' },
  info:     { label: 'Info',     className: 'badge-info' },
}

export default function SeverityBadge({ severity }: { severity: Severity }) {
  const cfg = CONFIG[severity] ?? CONFIG.info
  return <span className={cfg.className}>{cfg.label}</span>
}
