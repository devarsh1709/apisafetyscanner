/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base: '#08080f',
          surface: '#0f0f1a',
          card: '#14141f',
          elevated: '#1a1a2a',
          border: '#22223a',
        },
        brand: {
          50: '#eef2ff',
          100: '#e0e7ff',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
          info: '#3b82f6',
        },
      },
      fontFamily: {
        sans: ['-apple-system', 'BlinkMacSystemFont', 'Inter', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        card: '0 0 0 1px rgba(255,255,255,0.04), 0 4px 24px rgba(0,0,0,0.4)',
        glow: '0 0 20px rgba(99,102,241,0.2)',
        'glow-red': '0 0 20px rgba(239,68,68,0.15)',
      },
      animation: {
        'fade-up': 'fadeUp 0.4s ease forwards',
        'pulse-slow': 'pulse 3s ease infinite',
        'scan-line': 'scanLine 2s linear infinite',
      },
      keyframes: {
        fadeUp: {
          from: { opacity: '0', transform: 'translateY(16px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        scanLine: {
          '0%': { top: '0%' },
          '100%': { top: '100%' },
        },
      },
    },
  },
  plugins: [],
}
