import React from 'react'

const s: Record<string, React.CSSProperties> = {
  overlay: { position: 'absolute', top: 8, right: 8, width: 280, background: '#111827', border: '1px solid #1e3a5f', borderRadius: 8, padding: 14, fontSize: 11, zIndex: 10 },
  close: { position: 'absolute', top: 6, right: 10, cursor: 'pointer', color: '#5a6580', fontSize: 16, background: 'none', border: 'none' },
  title: { fontWeight: 700, fontSize: 13, color: '#e0e6f0', marginBottom: 8 },
  row: { display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid #1a2338' },
  label: { color: '#6b7a99' },
  val: { color: '#e0e6f0', fontWeight: 500 },
  riskBig: { fontSize: 22, fontWeight: 700, margin: '6px 0' },
  vulnList: { marginTop: 8 },
  vulnItem: { padding: '3px 0', borderBottom: '1px solid #1a2338', fontSize: 10 },
}

interface Props { node: any; onClose: () => void }

export function NodeTooltip({ node, onClose }: Props) {
  const riskColor = (node.risk_score || 0) >= 0.7 ? '#ff4757' : (node.risk_score || 0) >= 0.4 ? '#ffa502' : '#2ed573'

  return (
    <div style={s.overlay}>
      <button style={s.close} onClick={onClose}>&times;</button>
      <div style={s.title}>{node.hostname || node.host_id}</div>
      <div style={{ ...s.row, border: 'none' }}>
        <span style={s.label}>IP</span><span style={s.val}>{node.ip}</span>
      </div>
      <div style={s.row}><span style={s.label}>Privilege</span><span style={s.val}>{node.privilege}</span></div>
      <div style={s.row}><span style={s.label}>Zone</span><span style={s.val}>{node.zone}</span></div>
      <div style={s.row}><span style={s.label}>Type</span><span style={s.val}>{node.asset_type}</span></div>
      <div style={{ ...s.riskBig, color: riskColor }}>{((node.risk_score || 0) * 100).toFixed(0)}% risk</div>
      <div style={s.row}><span style={s.label}>Criticality</span><span style={s.val}>{(node.criticality || 0).toFixed(2)}</span></div>
      <div style={s.row}><span style={s.label}>Vulns</span><span style={s.val}>{node.vuln_count || 0}</span></div>
      <div style={s.row}><span style={s.label}>Max CVSS</span><span style={s.val}>{(node.max_cvss || 0).toFixed(1)}</span></div>
      <div style={s.row}><span style={s.label}>Exploit</span><span style={{ ...s.val, color: node.has_exploit ? '#ff4757' : '#2ed573' }}>{node.has_exploit ? 'Yes' : 'No'}</span></div>
      {node.is_absorbing && <div style={{ color: '#ff4757', fontWeight: 600, marginTop: 6 }}>★ CROWN JEWEL (Absorbing State)</div>}
      {node.is_entry && <div style={{ color: '#00d4ff', fontWeight: 600, marginTop: 6 }}>◎ Entry Point</div>}
    </div>
  )
}
