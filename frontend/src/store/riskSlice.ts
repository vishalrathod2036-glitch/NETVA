import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import { getRisk, getRiskPaths, getRiskSummary } from '../api/graph'

interface RiskState {
  stateMetrics: any[]
  criticalPaths: any[]
  summary: any | null
  loading: boolean
  error: string | null
}

const initialState: RiskState = { stateMetrics: [], criticalPaths: [], summary: null, loading: false, error: null }

export const fetchRisk = createAsyncThunk('risk/fetch', async () => {
  const [risk, paths, summary] = await Promise.all([getRisk(), getRiskPaths(), getRiskSummary()])
  return { stateMetrics: risk.state_metrics, criticalPaths: paths, summary }
})

export const riskSlice = createSlice({
  name: 'risk',
  initialState,
  reducers: {},
  extraReducers: (builder) => {
    builder
      .addCase(fetchRisk.pending, (s) => { s.loading = true; s.error = null })
      .addCase(fetchRisk.fulfilled, (s, a) => {
        s.loading = false
        s.stateMetrics = a.payload.stateMetrics
        s.criticalPaths = a.payload.criticalPaths
        s.summary = a.payload.summary
      })
      .addCase(fetchRisk.rejected, (s, a) => { s.loading = false; s.error = a.error.message || 'Failed' })
  },
})
