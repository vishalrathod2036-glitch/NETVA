import React, { useRef, useEffect, useState } from 'react'
import { useSelector } from 'react-redux'
import * as d3 from 'd3'
import type { RootState } from '../../main'
import { NodeTooltip } from './NodeTooltip'

const styles: Record<string, React.CSSProperties> = {
  container: { position: 'relative', width: '100%', height: 420, background: '#080c14', borderRadius: 8, overflow: 'hidden' },
  empty: { display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#3a4560', fontSize: 13 },
}

export function AttackGraph() {
  const svgRef = useRef<SVGSVGElement>(null)
  const { nodes, edges, loading } = useSelector((s: RootState) => s.graph)
  const [tooltip, setTooltip] = useState<any>(null)

  useEffect(() => {
    if (!svgRef.current || nodes.length === 0) return

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const width = svgRef.current.clientWidth
    const height = svgRef.current.clientHeight

    const g = svg.append('g')

    // Zoom
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => g.attr('transform', event.transform))
    svg.call(zoom)

    // Color scale: risk 1.0 → red, 0.0 → green
    const colorScale = d3.scaleSequential(d3.interpolateRdYlGn).domain([1, 0])

    // Build links/nodes for simulation
    const simNodes = nodes.map((n: any) => ({ ...n, id: n.state_id }))
    const simLinks = edges.map((e: any) => ({ ...e, source: e.source, target: e.target }))

    // Edges
    const link = g.append('g')
      .selectAll('line')
      .data(simLinks)
      .join('line')
      .attr('stroke', (d: any) => d.edge_type === 'lateral_movement' ? '#7b61ff' : '#1e3a5f')
      .attr('stroke-width', (d: any) => 1 + (d.weight || 0.5) * 2)
      .attr('stroke-dasharray', (d: any) => d.edge_type === 'lateral_movement' ? '6 3' : 'none')
      .attr('opacity', 0.6)

    // Nodes
    const node = g.append('g')
      .selectAll('g')
      .data(simNodes)
      .join('g')
      .style('cursor', 'pointer')
      .call(d3.drag<any, any>()
        .on('start', (e, d: any) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (e, d: any) => { d.fx = e.x; d.fy = e.y })
        .on('end', (e, d: any) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null })
      )

    // Node shapes
    node.each(function (d: any) {
      const el = d3.select(this)
      const r = 8 + (d.criticality || 0) * 12
      const color = d.is_entry ? '#00d4ff' : colorScale(d.risk_score || 0)

      if (d.is_absorbing) {
        // Diamond for absorbing
        const size = r * 1.5
        el.append('rect')
          .attr('width', size).attr('height', size)
          .attr('x', -size / 2).attr('y', -size / 2)
          .attr('transform', 'rotate(45)')
          .attr('fill', color).attr('stroke', '#fff').attr('stroke-width', 1.5)
      } else if (d.is_entry) {
        // Circle + ring for entry
        el.append('circle').attr('r', r + 4).attr('fill', 'none').attr('stroke', '#00d4ff').attr('stroke-width', 1.5)
        el.append('circle').attr('r', r).attr('fill', color)
      } else {
        el.append('circle').attr('r', r).attr('fill', color).attr('stroke', '#1e3a5f').attr('stroke-width', 1)
      }

      // Label
      el.append('text')
        .text(d.hostname || d.host_id || '')
        .attr('dy', r + 14)
        .attr('text-anchor', 'middle')
        .attr('fill', '#6b7a99')
        .attr('font-size', 9)
        .attr('font-family', 'JetBrains Mono, monospace')
    })

    node.on('click', (_e: any, d: any) => setTooltip(d))

    // Force simulation
    const simulation = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simLinks).id((d: any) => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide(30))

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y)

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`)
    })

    return () => { simulation.stop() }
  }, [nodes, edges])

  if (loading) return <div style={styles.container}><div style={styles.empty}>Loading graph...</div></div>
  if (nodes.length === 0) return <div style={styles.container}><div style={styles.empty}>Run a scan to generate the attack graph</div></div>

  return (
    <div style={styles.container}>
      <svg ref={svgRef} width="100%" height="100%" />
      {tooltip && <NodeTooltip node={tooltip} onClose={() => setTooltip(null)} />}
    </div>
  )
}
