import { useState } from 'react'
import axios from 'axios'

const DECISION_COLORS = { BLOCK: '#ff4444', MONITOR: '#ffaa00', IGNORE: '#00ff88' }

export default function Search() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState([])
  const [loading, setLoading] = useState(false)
  const [searched, setSearched] = useState(false)

  const search = async () => {
    if (!query.trim()) return
    setLoading(true)
    setSearched(true)
    try {
      const res = await axios.get(`/api/search?q=${encodeURIComponent(query)}&limit=50`)
      setResults(res.data)
    } catch (err) {
      console.error(err)
    }
    setLoading(false)
  }

  return (
    <div>
      <div style={{ color: '#00ff88', marginBottom: '24px', fontSize: '13px', letterSpacing: '1px' }}>
        // INTELLIGENCE SEARCH
      </div>
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && search()}
          placeholder="Search IOCs, malware, CVEs, domains, IPs..."
          style={{ flex: 1, background: '#0d1117', border: '1px solid #1e3a5f', borderRadius: '4px', padding: '12px 16px', color: '#e2e8f0', fontFamily: 'Courier New', fontSize: '14px', outline: 'none' }}
        />
        <button onClick={search} style={{ background: '#00ff88', color: '#0a0e1a', border: 'none', borderRadius: '4px', padding: '12px 24px', fontFamily: 'Courier New', fontWeight: 'bold', cursor: 'pointer', letterSpacing: '1px' }}>
          SEARCH
        </button>
      </div>
      <div style={{ marginBottom: '24px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {['emotet', 'cobalt strike', 'CVE-2026', 'ransomware'].map(q => (
          <button key={q} onClick={() => setQuery(q)} style={{ background: 'none', border: '1px solid #1e3a5f', borderRadius: '4px', padding: '4px 12px', color: '#4a6fa5', fontFamily: 'Courier New', fontSize: '11px', cursor: 'pointer' }}>
            {q}
          </button>
        ))}
      </div>
      {loading && <div style={{ color: '#00ff88' }}>// SEARCHING...</div>}
      {!loading && searched && results.length === 0 && (
        <div style={{ color: '#4a6fa5' }}>// NO RESULTS FOUND FOR "{query}"</div>
      )}
      {!loading && results.length > 0 && (
        <div>
          <div style={{ color: '#4a6fa5', fontSize: '11px', marginBottom: '16px' }}>// {results.length} RESULTS</div>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                {['TYPE', 'VALUE', 'CONFIDENCE', 'SOURCE', 'DECISION'].map(h => (
                  <th key={h} style={{ color: '#4a6fa5', fontSize: '11px', padding: '8px', textAlign: 'left', letterSpacing: '1px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #0d1117' }}>
                  <td style={{ padding: '10px 8px', color: '#9f7aea', fontSize: '12px' }}>{r.type}</td>
                  <td style={{ padding: '10px 8px', color: '#e2e8f0', fontSize: '12px', maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.value}</td>
                  <td style={{ padding: '10px 8px' }}>
                    <div style={{ background: '#1e3a5f', borderRadius: '2px', height: '4px', width: '80px' }}>
                      <div style={{ background: '#00ff88', height: '4px', width: `${r.confidence}%`, borderRadius: '2px' }} />
                    </div>
                    <span style={{ color: '#4a6fa5', fontSize: '10px' }}>{r.confidence}</span>
                  </td>
                  <td style={{ padding: '10px 8px', color: '#4a6fa5', fontSize: '11px' }}>{r.source}</td>
                  <td style={{ padding: '10px 8px' }}>
                    <span style={{ color: DECISION_COLORS[r.decision] || '#4a6fa5', fontSize: '11px', border: `1px solid ${DECISION_COLORS[r.decision] || '#4a6fa5'}`, padding: '2px 8px', borderRadius: '2px' }}>
                      {r.decision || '--'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
