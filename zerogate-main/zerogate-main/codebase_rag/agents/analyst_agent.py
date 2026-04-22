"""Analyst Agent — Evaluates the blast radius to confirm exploitability."""

from __future__ import annotations

import asyncio
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field

from ..api.models import VulnerabilityFinding
from ..config import settings
from .state import AgentState


class AnalystResponse(BaseModel):
    is_exploitable: bool = Field(description="True if the vulnerability is genuine and exploitable, False if it is a false positive.")
    reasoning: str = Field(description="Detailed explanation of the triage result based on the provided vulnerable code and blast radius.")


async def execute_analyst(state: AgentState) -> dict:
    """Evaluates the current vulnerability finding."""
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    
    if idx >= len(vulns):
        return {"is_exploitable": False, "analysis_reasoning": "No vulnerabilities left."}
        
    finding = vulns[idx]
    logger.info(f"Analyst Agent investigating: {finding.title}")

    # If it has no context beyond the initial seed, fallback to True securely
    if not finding.blast_radius:
        return {"is_exploitable": True, "analysis_reasoning": "Conservative fallback: No blast radius context available."}

    # Prepare context for the prompt
    context = ""
    for node in finding.blast_radius:
        # Load the file content
        file_path = Path(state["project_path"]) / node.file_path
        code = ""
        if file_path.exists():
            lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
            start = max(0, (node.start_line or 1) - 5)
            end = min(len(lines), (node.end_line or len(lines)) + 5)
            code = "".join(lines[start:end])
            
        context += f"File: {node.file_path} - Function: {node.qualified_name or node.function_name}\n"
        context += f"Code:\n```\n{code}\n```\n\n"

    prompt = (
        f"You are an expert security analyst. Review the following vulnerability finding:\n"
        f"Title: {finding.title}\n"
        f"Description: {finding.description}\n\n"
        f"Here is the code context from the blast radius analysis:\n"
        f"{context}\n\n"
        f"Determine if this is genuinely exploitable. Look for sanitization layers, "
        f"authentications, or mitigating controls in the calling graph. Provide your "
        f"reasoning and a boolean flag indicating if it is exploitable."
    )

    try:
        from pydantic_ai import Agent
        from ..services.llm import create_model
        from .. import constants as cs
        
        config = settings.get_agent_config(cs.ModelRole.ANALYST)
        model = create_model(config)
        agent = Agent(
            model,
            output_type=AnalystResponse,
            system_prompt=(
                "You are an elite security researcher. You analyze vulnerability "
                "reports alongside source code graphs to eliminate false positives. "
                "You must return the analysis as structured JSON data."
            ),
        )
        
        result = await agent.run(prompt)
        response = result.output
        
        return {
            "is_exploitable": response.is_exploitable,
            "analysis_reasoning": response.reasoning
        }
        
    except Exception as e:
        logger.warning(f"Analyst Agent evaluation failed: {e}")
        # Default to True so we don't accidentally silence a real bug
        return {
            "is_exploitable": True, 
            "analysis_reasoning": f"Fallback: Analysis failed due to {e}"
        }
