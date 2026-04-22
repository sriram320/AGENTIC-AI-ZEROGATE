"""Patcher Agent — Leverages LLMs to draft secure code fixes."""

from __future__ import annotations

import difflib
import uuid
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field

from ..api.models import FixProposal
from ..config import settings
from .state import AgentState


class PatchResponse(BaseModel):
    patched_code: str = Field(description="The complete, corrected source code replacing the vulnerable section. Preserve all indentation and formatting.")
    explanation: str = Field(description="A brief explanation of how the patch fixes the vulnerability.")


async def execute_patcher(state: AgentState) -> dict:
    """Generates an AST-aware patch for the confirmed vulnerability."""
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    
    if idx >= len(vulns) or not state.get("is_exploitable", False):
        return {"current_patch": None}
        
    finding = vulns[idx]
    logger.info(f"Patcher Agent generating fix for: {finding.title}")

    try:
        # Get target from the blast radius root (the seed)
        target = finding.blast_radius[0]
        file_path = target.file_path
        full_path = Path(state["project_path"]) / file_path

        if not full_path.exists():
            raise FileNotFoundError(f"Source file not found: {full_path}")

        source_lines = full_path.read_text(encoding="utf-8").splitlines(keepends=True)
        start = (target.start_line or 1) - 1
        end = target.end_line or len(source_lines)
        original_code = "".join(source_lines[start:end])

        prompt = (
            f"Vulnerability: {finding.category} — {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Analyst Note: {state.get('analysis_reasoning', '')}\n\n"
            f"Vulnerable code ({file_path}):\n"
            f"```\n{original_code}\n```\n\n"
            "Generate a secure replacement code block. You must only replace the "
            "vulnerable logic, preserving the function signature, indentation, and structure."
        )

        from pydantic_ai import Agent
        from ..services.llm import create_model
        from .. import constants as cs
        
        config = settings.get_agent_config(cs.ModelRole.PATCHER)
        model = create_model(config)
        agent = Agent(
            model,
            output_type=PatchResponse,
            system_prompt=(
                "You are an expert security engineer generating precise patches. "
                "You provide the corrected code block strictly inside the "
                "'patched_code' field. Do not include markdown fences in the "
                "'patched_code' itself. It must be valid code."
            ),
        )
        
        result = await agent.run(prompt)
        response = result.output
        patched_code = response.patched_code
        
        if patched_code.startswith("```"):
            # Strip markdown if the LLM hallucinated it into the field
            lines = patched_code.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            patched_code = "\n".join(lines) + "\n"

        # Generate unified diff
        diff = difflib.unified_diff(
            original_code.splitlines(keepends=True),
            patched_code.splitlines(keepends=True),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        unified_diff = "".join(diff)

        proposal = FixProposal(
            finding_id=finding.finding_id,
            original_code=original_code,
            patched_code=patched_code,
            unified_diff=unified_diff,
            explanation=response.explanation,
            file_path=file_path,
            function_name=target.function_name,
        )
        
        return {
            "current_patch": proposal,
            "all_fixes": [proposal]
        }
        
    except Exception as e:
        logger.error(f"Patcher Agent failed: {e}")
        return {"current_patch": None}
