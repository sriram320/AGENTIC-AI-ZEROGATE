"""Test-Gen Agent — Writes automated unit tests for generated patches."""

from __future__ import annotations

import os
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field

from .. import constants as cs
from ..api.models import FixProposal
from ..config import settings
from .state import AgentState


class TestGenResponse(BaseModel):
    test_code: str = Field(description="The complete python test file code using pytest that verifies the patched behavior.")


async def execute_testgen(state: AgentState) -> dict:
    """Generates a pytest verification file for the patched code."""
    patch: FixProposal | None = state.get("current_patch")
    
    if not patch:
        return {}
        
    project_path = Path(state["project_path"])
    file_path = project_path / patch.file_path
    
    # We only generate tests if the original file exists and we have a valid patch
    if not file_path.exists():
        return {}
        
    logger.info(f"Test-Gen Agent writing regression tests for {patch.file_path}")

    try:
        patched_file_content = file_path.read_text(encoding="utf-8")
        
        # Replace the vulnerable block with the patch to show the AI the fixed state 
        # that it needs to test against
        patched_file_content = patched_file_content.replace(patch.original_code, patch.patched_code)

        prompt = (
            f"You are a rigorous QA engineer. We just patched a vulnerability in `{patch.file_path}`.\n"
            f"Here is the explanation of the patch: {patch.explanation}\n\n"
            f"Here is the FULL source code of the patched file:\n"
            f"```python\n{patched_file_content}\n```\n\n"
            "Write a `pytest` compatible Python test script that tests this specific patched function. "
            "Ensure you import the correct module functions based on the file path. Return only the code."
        )

        from pydantic_ai import Agent
        from ..services.llm import create_model
        
        config = settings.get_agent_config(cs.ModelRole.TESTGEN)
        model = create_model(config)
        agent = Agent(
            model,
            output_type=TestGenResponse,
            system_prompt="You write precise, self-contained pytest scripts. Provide the raw python code in the test_code field.",
        )
        
        result = await agent.run(prompt)
        test_code = result.output.test_code
        
        if test_code.startswith("```"):
            lines = test_code.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            test_code = "\n".join(lines) + "\n"

        # Determine test file path
        # E.g. src/auth/login.py -> tests/test_login.py
        file_stem = file_path.stem
        # Ensure tests directory exists at root
        tests_dir = project_path / "tests"
        tests_dir.mkdir(exist_ok=True)
        
        test_file_path = tests_dir / f"test_{file_stem}_zerogate_{patch.finding_id[:6]}.py"
        test_file_path.write_text(test_code, encoding="utf-8")
        
        logger.success(f"Generated regression test at {test_file_path.name}")
        
        return {} # State modification handled internally by writing to disk for the verifier to pick up
        
    except Exception as e:
        logger.error(f"Test-Gen Agent failed: {e}")
        return {}
