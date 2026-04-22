import asyncio
import os
import sys
from pathlib import Path
from loguru import logger

# Add root project dir to path
root_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, root_dir)

from codebase_rag.api.routes.projects import _run_ingestion
from codebase_rag.api.state import project_store

async def run_end_to_end_test():
    """Runs the ingestion, scanning, and LangGraph multi-agent pipeline."""
    project_id = "test-e2e-project"
    test_path = Path("tests/dummy_vulnerable")
    
    logger.info(f"Running E2E tests against {test_path}...")
    project_store.create(project_id, test_path)
    
    # Run the entire pipeline (Memgraph ingestion, AutoScanner, Semgrep, Discovery LLM, LangGraph Agents)
    await _run_ingestion(project_id, test_path)
    
    state = project_store.get(project_id)
    report = state.report
    
    if not report:
        logger.error("No report was generated!")
        return
        
    logger.success(f"Report Generated! Found {len(report.findings)} findings.")
    for finding in report.findings:
        logger.info(f"- [{finding.severity.value}] {finding.category} in {finding.blast_radius[0].function_name}")
        if finding.fix_available:
            logger.success("  ✅ Fix was generated successfully:")
            print("====================================")
            print(finding.fix_diff)
            print("====================================")
        else:
            logger.warning("  ❌ No fix was generated.")

if __name__ == "__main__":
    asyncio.run(run_end_to_end_test())
