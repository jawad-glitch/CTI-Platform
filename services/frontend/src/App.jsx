import { useState } from 'react'
import Dashboard from './pages/Dashboard.jsx'
import Search from './pages/Search.jsx'
import CVEs from './pages/CVEs.jsx'
import Threats from './pages/Threats.jsx'

const NAV_ITEMS = [
  { id: 'dashboard', label: '// DASHBOARD' },
  { id: 'search',    label: '// SEARCH' },
  { id: 'cves',      label: '// CVEs' },
  { id: 'threats',   label: '// THREATS' },
]

export default function App() {
  const [page, setPage] = useState('dashboard')

  return (
    <div style={{ minHeight: '100vh', background: '#0a0e1a' }}>
      {/* Top nav */}
      <nav style={{
        borderBottom: '1px solid #1e3a5f',
        padding: '12px 24px',
        display: 'flex',
        alignItems: 'center',
        gap: '32px',
        background: '#0d1117'
      }}>
        <div style={{ color: '#00ff88', fontWeight: 'bold', fontSize: '18px', letterSpacing: '2px' }}>
          ◈ CTI PLATFORM
        </div>
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            onClick={() => setPage(item.id)}
            style={{
              background: 'none',
              border: 'none',
              color: page === item.id ? '#00ff88' : '#4a6fa5',
              cursor: 'pointer',
              fontSize: '13px',
              letterSpacing: '1px',
              fontFamily: 'Courier New',
              borderBottom: page === item.id ? '1px solid #00ff88' : 'none',
              paddingBottom: '2px'
            }}
          >
            {item.label}
          </button>
        ))}
        <div style={{ marginLeft: 'auto', color: '#1e3a5f', fontSize: '11px' }}>
          {new Date().toUTCString()}
        </div>
      </nav>

      {/* Page content */}
      <main style={{ padding: '24px' }}>
        {page === 'dashboard' && <Dashboard />}
        {page === 'search'    && <Search />}
        {page === 'cves'      && <CVEs />}
        {page === 'threats'   && <Threats />}
      </main>
    </div>
  )
}
