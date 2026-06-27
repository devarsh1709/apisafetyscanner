import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'
import Reports from './pages/Reports'

export default function App() {
  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan/new" element={<NewScan />} />
          <Route path="/scan/:id" element={<ScanDetail />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
}
