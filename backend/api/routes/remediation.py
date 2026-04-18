"""Remediation routes — MDP policy, action catalogue, simulation."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.api.state import app_state
from backend.api.schemas import RemediationResponse, RemediationStep
from backend.mdp.action_space import get_all_actions, ACTION_MAP
from backend.mdp.simulator import Simulator

router = APIRouter()


class SimulateRequest(BaseModel):
    action_id: str
    target_asset_id: str


@router.get("/remediation")
async def get_remediation() -> RemediationResponse:
    """MDP optimal policy steps."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    policy = app_state.current_run.policy
    if policy is None:
        raise HTTPException(status_code=425, detail="MDP policy not yet computed.")

    steps = [RemediationStep(**s) for s in policy.to_dict()["steps"]]

    return RemediationResponse(
        steps=steps,
        initial_risk=policy.initial_risk,
        final_risk=policy.final_risk,
        total_risk_reduction=policy.total_risk_reduction,
        total_cost=policy.total_cost,
        total_disruption=policy.total_disruption,
        cumulative_reward=policy.cumulative_reward,
        training_episodes=policy.training_episodes,
    )


@router.get("/remediation/actions")
async def get_action_catalogue() -> list[dict]:
    """Return all available defender actions."""
    actions = get_all_actions()
    return [
        {
            "action_id": a.action_id,
            "action_type": a.action_type,
            "label": a.label,
            "description": a.description,
            "target_type": a.target_type,
            "cost": a.cost,
            "disruption": a.disruption,
            "applies_to_port": a.applies_to_port,
        }
        for a in actions
    ]


@router.post("/remediation/simulate")
async def simulate_action(req: SimulateRequest) -> dict:
    """What-if simulation — preview action effect before executing."""
    if not app_state.ready:
        raise HTTPException(status_code=425, detail="Pipeline not yet complete.")

    run = app_state.current_run

    if req.action_id not in ACTION_MAP:
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action_id}")

    simulator = Simulator()
    result = simulator.simulate_action(
        action_id=req.action_id,
        target_asset_id=req.target_asset_id,
        state=run.posture,
        amc=run.amc,
        G=run.G,
        network=run.network,
    )

    return result.to_dict()
