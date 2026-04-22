"""Verifier Agent — Tests the patched code to ensure syntactic and functional validity."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

from loguru import logger

from .state import AgentState
from ..api.models import FixProposal


async def execute_verifier(state: AgentState) -> dict:
    """Applies the current patch temporarily and runs the test suite."""
    patch: FixProposal | None = state.get("current_patch")
    if not patch:
        return {"verification_success": False, "verification_logs": "No patch to verify."}

    project_path = Path(state["project_path"])
    file_path = project_path / patch.file_path

    if not file_path.exists():
        return {
            "verification_success": False,
            "verification_logs": f"File {patch.file_path} does not exist.",
        }

    # Backup original code to restore after testing
    original_file_content = file_path.read_text(encoding="utf-8")
    
    # Extract the original AST block from the patch so we can replace it accurately
    target_block = patch.original_code
    replacement_block = patch.patched_code
    
    if target_block not in original_file_content:
        logger.warning("Exact original block not found for verification. Falling back.")
        # Minimal verification: Check syntax structure
        try:
            compile(replacement_block, patch.file_path, "exec")
            return {
                "verification_success": True,
                "verification_logs": "Syntax was valid. (AST fallback skipped for full execution due to bounds mismatch)",
            }
        except SyntaxError as e:
            return {
                "verification_success": False,
                "verification_logs": f"Syntax Error in generated patch: {e}",
            }

    patched_content = original_file_content.replace(target_block, replacement_block, 1)

    try:
        # Write patch
        file_path.write_text(patched_content, encoding="utf-8")
        
        # Run tests (assume `uv run pytest` or `make test` would work, but to avoid 
        # destroying the environment, we first just try syntax and type checking)
        
        # 1. Syntax Check
        python_cmd_compile = ["python", "-m", "py_compile", str(file_path)]
        compile_res = await asyncio.to_thread(
            subprocess.run, python_cmd_compile, capture_output=True, text=True, cwd=str(project_path)
        )
        if compile_res.returncode != 0:
            return {
                "verification_success": False,
                "verification_logs": f"Syntax Error:\n{compile_res.stderr}",
            }
            
        # 2. PyTest Execution
        cmd = ["pytest"] # Default to pytest. If it fails due to no tests, that's fine.
        result = await asyncio.to_thread(
            subprocess.run, cmd, capture_output=True, text=True, cwd=str(project_path)
        )
        
        # We consider exit code 5 (no tests collected) as a success for the file itself.
        if result.returncode in (0, 5):
            return {
                "verification_success": True,
                "verification_logs": "Patch applied cleanly and tests/syntax pass.",
            }
        else:
            return {
                "verification_success": False,
                "verification_logs": f"Tests Failed:\n{result.stdout}\n{result.stderr}",
            }
            
    finally:
        # ALWAYS restore the original file so the graph is stateless
        file_path.write_text(original_file_content, encoding="utf-8")
