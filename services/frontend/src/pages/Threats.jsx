import { useState, useEffect } from 'react'
import axios from 'axios'

const DECISION_COLORS = { BLOCK: '#ff4444', MONITOR: '#ffaa00', IGNORE: '#00ff88' }

export default function Threats() {
  const [threats, setThreats] = useState([])
  const [filter, setFilter] = useState('BLOCK')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    axios.get(`/api/decisions?decision=${filter}&limit=100`)
      .then(res => {
        setThreats(res.data)
        setLoading(false)
      })
  }, [filter])

  return (
    <div>
      <div style={{ color: '#00ff88', marginBottom: '24px', fontSize: '13px', letterSpacing: '1px' }}>
        // THREAT INTELLIGENCE -- ACTIONABLE IOCs
      </div>
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        {['BLOCK', 'MONITOR', 'IGNORE'].map(d => (
          <button key={d} onClick={() => setFilter(d)} style={{ background: filter === d ? DECISION_COLORS[d] : 'none', color: filter === d ? '#0a0e1a' : DECISION_COLORS[d], border: `1px solid ${DECISION_COLORS[d]}`, borderRadius: '4px', padding: '8px 20px', fontFamily: 'Courier New', fontSize: '12px', cursor: 'pointer', letterSpacing: '1px', fontWeight: 'bold' }}>
            {d}
          </button>
        ))}
      </div>
      {loading && <div style={{ color: '#00ff88' }}>// LOADING...</div>}
      {!loading && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
              {['TYPE', 'VALUE', 'THREAT SCORE', 'SOURCE', 'REASONING'].map(h => (
                <th key={h} style={{ color: '#4a6fa5', fontSize: '11px', padding: '8px', textAlign: 'left', letterSpacing: '1px' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {threats.map((t, i) => (
              <tr key={i} style={{ borderBottom: '1px solid #0d1117' }}>
                <td style={{ padding: '10px 8px', color: '#9f7aea', fontSize: '12px' }}>{t.type}</td>
                <td style={{ padding: '10px 8px', color: '#e2e8f0', fontSize: '12px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.value}</td>
                <td style={{ padding: '10px 8px' }}>
                  <span style={{ color: DECISION_COLORS[t.decision], fontWeight: 'bold' }}>{t.threat_score}</span>
                  <span style={{ color: '#1e3a5f' }}>/100</span>
                </td>
                <td style={{ padding: '10px 8px', color: '#4a6fa5', fontSize: '11px' }}>{t.source}</td>
                <td style={{ padding: '10px 8px', color: '#4a6fa5', fontSize: '10px', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{t.reasoning}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
