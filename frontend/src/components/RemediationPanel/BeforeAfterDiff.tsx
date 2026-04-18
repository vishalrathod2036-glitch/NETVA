import React from 'react'

const s: Record<string, React.CSSProperties> = {
  container: { background: '#0d1320', border: '1px solid #1e2a42', borderRadius: 6, padding: 12, fontSize: 11 },
  row: { display: 'flex', justifyContent: 'space-between', padding: '3px 0' },
  label: { color: '#6b7a99' },
  before: { color: '#ff4757' },
  after: { color: '#2ed573' },
  arrow: { color: '#5a6580', margin: '0 6px' },
}

interface Props { data: any }

export function BeforeAfterDiff({ data }: Props) {
  if (!data) return null

  return (
    <div style={s.container}>
      <div style={s.row}>
        <span style={s.label}>Risk</span>
        <span>
          <span style={s.before}>{(data.risk_before * 100).toFixed(1)}%</span>
          <span style={s.arrow}>→</span>
          <span style={s.after}>{(data.risk_after * 100).toFixed(1)}%</span>
        </span>
      </div>
      <div style={s.row}>
        <span style={s.label}>Edges</span>
        <span>
          <span style={s.before}>{data.edges_before}</span>
          <span style={s.arrow}>→</span>
          <span style={s.after}>{data.edges_after}</span>
        </span>
      </div>
      {data.removed_edges?.length > 0 && (
        <div style={{ marginTop: 6, fontSize: 10, color: '#5a6580' }}>
          Removed: {data.removed_edges.map((e: any) => `${e.from}→${e.to}`).join(', ')}
        </div>
      )}
    </div>
  )
}
