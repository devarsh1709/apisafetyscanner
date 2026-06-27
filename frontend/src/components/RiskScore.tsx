import clsx from 'clsx'

function riskLabel(score: number) {
  if (score >= 8) return { label: 'Critical Risk', color: 'text-red-400', ring: 'stroke-red-500' }
  if (score >= 6) return { label: 'High Risk', color: 'text-orange-400', ring: 'stroke-orange-500' }
  if (score >= 4) return { label: 'Medium Risk', color: 'text-yellow-400', ring: 'stroke-yellow-500' }
  if (score >= 2) return { label: 'Low Risk', color: 'text-green-400', ring: 'stroke-green-500' }
  return { label: 'Minimal Risk', color: 'text-blue-400', ring: 'stroke-blue-500' }
}

export default function RiskScore({ score }: { score: number }) {
  const { label, color, ring } = riskLabel(score)
  const pct = (score / 10) * 100
  const radius = 40
  const circ = 2 * Math.PI * radius
  const dash = (pct / 100) * circ

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-28 h-28">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
          <circle cx="50" cy="50" r={radius} strokeWidth="8" className="stroke-bg-border fill-none" />
          <circle
            cx="50"
            cy="50"
            r={radius}
            strokeWidth="8"
            className={clsx('fill-none transition-all duration-700', ring)}
            strokeDasharray={`${dash} ${circ - dash}`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={clsx('text-2xl font-bold', color)}>{score.toFixed(1)}</span>
          <span className="text-[10px] text-slate-500">/ 10</span>
        </div>
      </div>
      <span className={clsx('text-xs font-semibold', color)}>{label}</span>
    </div>
  )
}
