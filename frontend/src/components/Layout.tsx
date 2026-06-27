import React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, Plus, FileText, Zap } from 'lucide-react'
import clsx from 'clsx'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
  { to: '/scan/new', icon: Plus, label: 'New Scan', exact: false },
  { to: '/reports', icon: FileText, label: 'Reports', exact: false },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen bg-bg-base">
      <aside className="w-60 shrink-0 flex flex-col border-r border-bg-border bg-bg-surface">
        <div className="px-6 py-5 border-b border-bg-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
              <Shield className="w-5 h-5 text-brand-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-white leading-tight">API Scanner</p>
              <p className="text-[10px] text-slate-500 leading-tight mt-0.5">Security Auditor</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-0.5">
          {navItems.map(({ to, icon: Icon, label, exact }) => (
            <NavLink
              key={to}
              to={to}
              end={exact}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150',
                  isActive
                    ? 'bg-brand-500/10 text-brand-400 border border-brand-500/15'
                    : 'text-slate-400 hover:text-white hover:bg-bg-elevated'
                )
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-4 py-4 border-t border-bg-border">
          <div className="rounded-xl bg-bg-elevated border border-bg-border px-3 py-2.5">
            <div className="flex items-center gap-2 mb-1.5">
              <Zap className="w-3.5 h-3.5 text-brand-400" />
              <span className="text-[11px] font-semibold text-white">9 Scan Modules</span>
            </div>
            <p className="text-[10px] text-slate-500 leading-relaxed">
              Auth · Rate Limits · Injection · CORS · Headers · SSL · IDOR · Disclosure · Methods
            </p>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  )
}
