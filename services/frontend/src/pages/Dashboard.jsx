import { useState, useEffect } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import axios from 'axios'

const COLORS = { BLOCK: '#ff4444', MONITOR: '#ffaa00', IGNORE: '#00ff88' }

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: '#0d1117', border: `1px solid ${color || '#1e3a5f'}`, borderRadius: '4px', padding: '20px', minWidth: '160px' }}>
      <div style={{ color: '#4a6fa5', fontSize: '11px', letterSpacing: '1px' }}>{label}</div>
      <div style={{ color: color || '#e2e8f0', fontSize: '32px', fontWeight: 'bold', marginTop: '8px' }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      axios.get('/api/stats'),
      axios.get('/taxii/reports/daily')
    ]).then(([statsRes, reportRes]) => {
      setStats(statsRes.data)
      setReport(reportRes.data)
      setLoading(false)
    }).catch(err => {
      console.error(err)
      setLoading(false)
    })
  }, [])

  if (loading) return <div style={{ color: '#00ff88' }}>// LOADING INTELLIGENCE DATA...</div>
  if (!stats || !report) return <div style={{ color: '#ff4444' }}>// ERROR: CANNOT REACH API</div>

  const decisionData = [
    { name: 'BLOCK', value: report.summary.block },
    { name: 'MONITOR', value: report.summary.monitor },
    { name: 'IGNORE', value: report.summary.ignore },
  ]

  const sourceData = report.intelligence_sources.map(s => ({
    name: s.source.replace('AlienVault ', ''),
    iocs: s.ioc_count
  }))

  return (
    <div>
      <div style={{ color: '#00ff88', marginBottom: '24px', fontSize: '13px', letterSpacing: '1px' }}>
        // DAILY EXECUTIVE CYBER BRIEF -- {report.generated_at}
      </div>

      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', marginBottom: '32px' }}>
        <StatCard label="TOTAL IOCs" value={report.summary.total_iocs} />
        <StatCard label="BLOCK" value={report.summary.block} color="#ff4444" />
        <StatCard label="MONITOR" value={report.summary.monitor} color="#ffaa00" />
        <StatCard label="IGNORE" value={report.summary.ignore} color="#00ff88" />
        <StatCard label="RELATIONSHIPS" value={stats.relationships} color="#4a6fa5" />
        <StatCard label="CAMPAIGNS" value={stats.objects.campaign || 0} color="#9f7aea" />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '32px' }}>
        <div style={{ background: '#0d1117', border: '1px solid #1e3a5f', borderRadius: '4px', padding: '20px' }}>
          <div style={{ color: '#4a6fa5', fontSize: '11px', letterSpacing: '1px', marginBottom: '16px' }}>DECISION BREAKDOWN</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={decisionData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                {decisionData.map((entry) => (
                  <Cell key={entry.name} fill={COLORS[entry.name]} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1e3a5f', color: '#e2e8f0' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: '#0d1117', border: '1px solid #1e3a5f', borderRadius: '4px', padding: '20px' }}>
          <div style={{ color: '#4a6fa5', fontSize: '11px', letterSpacing: '1px', marginBottom: '16px' }}>IOCs BY SOURCE</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={sourceData}>
              <XAxis dataKey="name" tick={{ fill: '#4a6fa5', fontSize: 10 }} />
              <YAxis tick={{ fill: '#4a6fa5', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid #1e3a5f', color: '#e2e8f0' }} />
              <Bar dataKey="iocs" fill="#00ff88" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        <div style={{ background: '#0d1117', border: '1px solid #1e3a5f', borderRadius: '4px', padding: '20px' }}>
          <div style={{ color: '#4a6fa5', fontSize: '11px', letterSpacing: '1px', marginBottom: '16px' }}>TOP MALWARE FAMILIES</div>
          {report.top_malware_families.map((m, i) => (
            <div key={m} style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
              <span style={{ color: '#ff4444', fontSize: '11px' }}>{String(i + 1).padStart(2, '0')}</span>
              <span style={{ color: '#e2e8f0' }}>{m}</span>
            </div>
          ))}
        </div>

        <div style={{ background: '#0d1117', border: '1px solid #1e3a5f', borderRadius: '4px', padding: '20px' }}>
          <div style={{ color: '#4a6fa5', fontSize: '11px', letterSpacing: '1px', marginBottom: '16px' }}>TOP ATT&CK TECHNIQUES</div>
          {report.top_attack_techniques.map((t, i) => (
            <div key={t} style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
              <span style={{ color: '#ffaa00', fontSize: '11px' }}>{String(i + 1).padStart(2, '0')}</span>
              <span style={{ color: '#e2e8f0' }}>{t}</span>
              <a href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`} target="_blank" rel="noreferrer" style={{ color: '#4a6fa5', fontSize: '11px', marginLeft: 'auto' }}>MITRE</a>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
