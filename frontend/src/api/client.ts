import axios from 'axios'
import type { Scan, ScanDetail, ScanStats, Vulnerability } from '../types'

const api = axios.create({ baseURL: '/api' })

export const scanApi = {
  list: async (skip = 0, limit = 50) => {
    const { data } = await api.get<{ scans: Scan[]; total: number }>('/scans/', { params: { skip, limit } })
    return data
  },

  create: async (payload: {
    target_url: string
    name?: string
    scan_types?: string[]
    headers?: Record<string, string>
    cookies?: Record<string, string>
    auth_token?: string
  }) => {
    const { data } = await api.post<Scan>('/scans/', payload)
    return data
  },

  get: async (id: string) => {
    const { data } = await api.get<Scan>(`/scans/${id}`)
    return data
  },

  getVulnerabilities: async (id: string, severity?: string) => {
    const { data } = await api.get<{ vulnerabilities: Vulnerability[]; total: number }>(
      `/scans/${id}/vulnerabilities`,
      { params: severity ? { severity } : {} }
    )
    return data
  },

  getLog: async (id: string) => {
    const { data } = await api.get(`/scans/${id}/log`)
    return data
  },

  delete: async (id: string) => {
    await api.delete(`/scans/${id}`)
  },

  stats: async () => {
    const { data } = await api.get<ScanStats>('/scans/stats/overview')
    return data
  },
}

export const reportApi = {
  getJson: async (id: string) => {
    const { data } = await api.get(`/reports/${id}/json`)
    return data
  },

  downloadMarkdown: async (id: string) => {
    const resp = await api.get(`/reports/${id}/markdown`, { responseType: 'blob' })
    const url = URL.createObjectURL(new Blob([resp.data]))
    const a = document.createElement('a')
    a.href = url
    a.download = `report-${id.slice(0, 8)}.md`
    a.click()
    URL.revokeObjectURL(url)
  },
}

export function createScanWebSocket(scanId: string, onMessage: (data: unknown) => void): WebSocket {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const ws = new WebSocket(`${proto}://${window.location.host}/ws/scan/${scanId}`)
  ws.onmessage = (e) => onMessage(JSON.parse(e.data))
  return ws
}
