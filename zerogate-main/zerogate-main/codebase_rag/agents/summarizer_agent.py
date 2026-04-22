"""Summarizer Agent — Aggregates and finalizes the executive security report."""

from __future__ import annotations

import json

from loguru import logger
from pydantic import BaseModel, Field

from .. import constants as cs
from ..api.models import FixProposal, VulnerabilityFinding
from ..config import settings
from .state import AgentState


class SummaryResponse(BaseModel):
    executive_summary: str = Field(description="A 2-3 paragraph executive summary of the security posture, critical findings, and remediation actions.")


async def execute_summarizer(state: AgentState) -> dict:
    """Executes at the end of the graph to summarize the findings and fixes."""
    
    vulns: list[VulnerabilityFinding] = state.get("vulnerabilities", [])
    fixes: list[FixProposal] = state.get("all_fixes", [])
    
    if not vulns:
        return {"executive_summary": "No vulnerabilities detected."}
        
    logger.info("Summarizer Agent generating executive report...")

    try:
        # Build context
        context = []
        for v in vulns:
            fix = next((f for f in fixes if f.finding_id == v.finding_id), None)
            context.append({
                "title": v.title,
                "severity": v.severity,
                "is_patched": v.fix_available or bool(fix),
                "patch_explanation": fix.explanation if fix else "False positive or patch failed.",
                "file": fix.file_path if fix else None
            })

        prompt = (
            "You are a CISO (Chief Information Security Officer) generating an executive summary report.\n"
            f"Review the following JSON data representing the vulnerabilities found and patched by our AI Agents:\n"
            f"{json.dumps(context, indent=2)}\n\n"
            "Write a concise, high-level impact summary. Highlight the critical risks that were discovered and remediated."
        )

        from pydantic_ai import Agent
        from ..services.llm import create_model
        
        config = settings.get_agent_config(cs.ModelRole.SUMMARIZER)
        model = create_model(config)
        agent = Agent(
            model,
            output_type=str,
            system_prompt="You generate formal markdown security impact summaries.",
        )
        
        result = await agent.run(prompt)
        
        # We could store this on the state or directly inject it into the final project report.
        # For LangGraph state tracking, we'll assign it to a new state var.
        
        return {"executive_summary": result.output}
        
    except Exception as e:
        logger.error(f"Summarizer Agent failed: {e}")
        return {"executive_summary": "Summary generation failed."}
