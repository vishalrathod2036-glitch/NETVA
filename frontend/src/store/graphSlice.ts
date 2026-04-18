import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import { getGraph } from '../api/graph'

interface GraphState {
  nodes: any[]
  edges: any[]
  loading: boolean
  error: string | null
}

const initialState: GraphState = { nodes: [], edges: [], loading: false, error: null }

export const fetchGraph = createAsyncThunk('graph/fetch', async () => {
  const data = await getGraph()
  return data
})

export const graphSlice = createSlice({
  name: 'graph',
  initialState,
  reducers: {
    setGraph: (state, action) => { state.nodes = action.payload.nodes; state.edges = action.payload.edges },
    clearGraph: (state) => { state.nodes = []; state.edges = [] },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchGraph.pending, (state) => { state.loading = true; state.error = null })
      .addCase(fetchGraph.fulfilled, (state, action) => {
        state.loading = false
        state.nodes = action.payload.nodes
        state.edges = action.payload.edges
      })
      .addCase(fetchGraph.rejected, (state, action) => {
        state.loading = false
        state.error = action.error.message || 'Failed to fetch graph'
      })
  },
})

export const { setGraph, clearGraph } = graphSlice.actions
