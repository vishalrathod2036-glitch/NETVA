import React from 'react'
import { useSelector } from 'react-redux'
import type { RootState } from '../../main'
import { ActionCard } from './ActionCard'
import { BeforeAfterDiff } from './BeforeAfterDiff'

const s: Record<string, React.CSSProperties> = {
  container: { display: 'flex', flexDirection: 'column', gap: 8 },
  summary: { display: 'flex', gap: 16, padding: '8px 0', borderBottom: '1px solid #1a2338', fontSize: 11, color: '#8892a6', flexWrap: 'wrap' },
  summaryVal: { fontWeight: 600, color: '#e0e6f0' },
  riskBar: { display: 'flex', alignItems: 'center', gap: 8, padding: '8px 0' },
  barTrack: { flex: 1, height: 6, borderRadius: 3, background: '#1a2338' },
  barFill: { height: 6, borderRadius: 3, transition: 'width 0.5s ease' },
  empty: { color: '#3a4560', fontSize: 12, padding: 16 },
}

export function ActionQueue() {
  const { steps, policy, loading } = useSelector((st: RootState) => st.remediation)

  if (loading) return <div style={s.empty}>Loading remediation policy...</div>
  if (!steps || steps.length === 0) return <div style={s.empty}>Run a scan to generate the optimal defense sequence</div>

  const initial = policy?.initial_risk || 1.0
  const final = policy?.final_risk || 0.0
  const reduction = policy?.total_risk_reduction || 0.0

  return (
    <div style={s.container}>
      <div style={s.summary}>
        <span>Risk: <span style={{ ...s.summaryVal, color: '#ff4757' }}>{(initial * 100).toFixed(0)}%</span> → <span style={{ ...s.summaryVal, color: '#2ed573' }}>{(final * 100).toFixed(0)}%</span></span>
        <span>Reduction: <span style={{ ...s.summaryVal, color: '#2ed573' }}>{(reduction * 100).toFixed(1)}%</span></span>
        <span>Steps: <span style={s.summaryVal}>{steps.length}</span></span>
        <span>Cost: <span style={s.summaryVal}>{(policy?.total_cost || 0).toFixed(2)}</span></span>
        <span>Disruption: <span style={s.summaryVal}>{(policy?.total_disruption || 0).toFixed(2)}</span></span>
      </div>

      <div style={s.riskBar}>
        <span style={{ fontSize: 10, color: '#ff4757' }}>{(initial * 100).toFixed(0)}%</span>
        <div style={s.barTrack}>
          <div style={{ ...s.barFill, width: `${(1 - reduction) * 100}%`, background: 'linear-gradient(90deg, #2ed573, #ffa502, #ff4757)' }} />
        </div>
        <span style={{ fontSize: 10, color: '#2ed573' }}>{(final * 100).toFixed(0)}%</span>
      </div>

      <div style={{ display: 'flex', gap: 8, overflowX: 'auto', paddingBottom: 8 }}>
        {steps.map((step: any) => (
          <ActionCard key={step.step} step={step} />
        ))}
      </div>
    </div>
  )
}
