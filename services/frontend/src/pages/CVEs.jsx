import { useState, useEffect } from 'react'
import axios from 'axios'

export default function CVEs() {
  const [cves, setCves] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    axios.get('/api/objects?type=cve&min_confidence=0&limit=100')
      .then(res => {
        setCves(res.data)
        setLoading(false)
      })
  }, [])

  if (loading) return <div style={{ color: '#00ff88' }}>// LOADING CVEs...</div>

  return (
    <div>
      <div style={{ color: '#00ff88', marginBottom: '24px', fontSize: '13px', letterSpacing: '1px' }}>
        // VULNERABILITY INTELLIGENCE -- {cves.length} CVEs TRACKED
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
            {['CVE ID', 'CONFIDENCE', 'SOURCE', 'FIRST SEEN', 'LAST SEEN', 'LINK'].map(h => (
              <th key={h} style={{ color: '#4a6fa5', fontSize: '11px', padding: '8px', textAlign: 'left', letterSpacing: '1px' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {cves.map((cve, i) => (
            <tr key={i} style={{ borderBottom: '1px solid #0d1117' }}>
              <td style={{ padding: '10px 8px', color: '#ffaa00', fontSize: '13px', fontWeight: 'bold' }}>{cve.value}</td>
              <td style={{ padding: '10px 8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ background: '#1e3a5f', borderRadius: '2px', height: '4px', width: '60px' }}>
                    <div style={{
                      background: cve.confidence >= 85 ? '#ff4444' : cve.confidence >= 50 ? '#ffaa00' : '#00ff88',
                      height: '4px',
                      width: `${cve.confidence}%`,
                      borderRadius: '2px'
                    }} />
                  </div>
                  <span style={{ color: '#4a6fa5', fontSize: '10px' }}>{cve.confidence}</span>
                </div>
              </td>
              <td style={{ padding: '10px 8px', color: '#4a6fa5', fontSize: '11px' }}>{cve.source}</td>
              <td style={{ padding: '10px 8px', color: '#4a6fa5', fontSize: '11px' }}>
                {new Date(cve.first_seen).toLocaleDateString()}
              </td>
              <td style={{ padding: '10px 8px', color: '#4a6fa5', fontSize: '11px' }}>
                {new Date(cve.last_seen).toLocaleDateString()}
              </td>
              <td style={{ padding: '10px 8px' }}>
                <a href={`https://nvd.nist.gov/vuln/detail/${cve.value}`} target="_blank" rel="noreferrer" style={{ color: '#4a6fa5', fontSize: '11px' }}>
                  NVD
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
