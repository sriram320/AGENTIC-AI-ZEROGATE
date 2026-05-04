"""SQL Injection Agent."""

from __future__ import annotations

from loguru import logger
from pydantic_ai import Agent

from ..api.models import ThreatObject
from ..config import settings
from .state import AgentState

system_prompt = """You are a deterministic AST analysis engine specialising in SQL Injection. You do not write prose. You only output JSON matching the provided schema.
Follow this Chain-of-Thought Verification Template:
1. Identify the Sink: Determine if the vulnerable code execution involves a database sink (e.g. cursor.execute).
2. Trace the Source: Determine where the input payload originates.
3. Identify Sanitization: Is the input sanitized, parameterized, or cast before reaching the sink?
4. Final Verdict: VULNERABLE if unsanitized user input is concatenated (via +, %s, f-strings, or .format) into the query. CLEAN if the query is explicitly parameterized (e.g., using '?', ':1', or tuple arguments), cast to an integer, or executed safely via an ORM (e.g., .filter(), .get()).

CRITICAL: Your output MUST be valid JSON matching ThreatObject schema exactly.
Required fields: sink, source, path (array), severity (CRITICAL|HIGH|MEDIUM|LOW),
verdict (VULNERABLE|CLEAN|LOW_CONFIDENCE|UNREACHABLE), reasoning_chain (array), agent_name.
Do NOT include any text outside the JSON object."""

async def execute_sqli_agent(state: AgentState) -> dict:
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    if idx >= len(vulns):
        return {}
        
    finding = vulns[idx]
    logger.info(f"SQLi Agent investigating: {finding.title}")

    context = f"Title: {finding.title}\nDescription: {finding.description}\nBlast Radius Files:\n"
    for node in finding.blast_radius:
        context += f"- {node.file_path} in {node.function_name}\n"

    try:
        from ..services.llm import create_model
        from .. import constants as cs
        
        config = settings.get_agent_config(cs.ModelRole.ANALYST)
        # Use temperature 0.0 as per the report
        config.to_update_kwargs()["temperature"] = 0.0 
        model = create_model(config)
        
        agent = Agent(
            model,
            system_prompt=system_prompt,
            output_type=ThreatObject,
            retries=3,
        )
        
        # Inject context (Context Injection Block)
        result = await agent.run(context)
        threat = result.output
        threat.agent_name = "SQLiAgent"
        
        return {"identified_threats": [threat]}
        
    except Exception as e:
        logger.warning(f"SQLi Agent evaluation failed: {e}")
        return {}
