"""Remote Code Execution (RCE) Agent."""

from __future__ import annotations

from loguru import logger
from pydantic_ai import Agent

from ..api.models import ThreatObject
from ..config import settings
from .state import AgentState

system_prompt = """You are a deterministic AST analysis engine specialising in Remote Code Execution (RCE). You do not write prose. You only output JSON matching the provided schema.
Follow this Chain-of-Thought Verification Template:
1. Identify the Sink: Query Memgraph caller/callee graph to verify if os.system(), subprocess.run(), eval(), exec(), Runtime.exec(), or os/exec are reachable.
2. Trace the Source: Determine if external payloads map to this sink.
3. Identify Sanitization: Is the payload neutralized or strictly validated against an allowlist?
4. Final Verdict: VULNERABLE if the execution sink directly incorporates unvalidated user input. CLEAN if the input is validated against a strict allowlist (e.g., `if input in ALLOWED:`), checked with `isalnum()`, or if `subprocess.run/check_call` is used safely with `shell=False` and a list of arguments rather than a raw string.

CRITICAL: Your output MUST be valid JSON matching ThreatObject schema exactly.
Required fields: sink, source, path (array), severity (CRITICAL|HIGH|MEDIUM|LOW),
verdict (VULNERABLE|CLEAN|LOW_CONFIDENCE|UNREACHABLE), reasoning_chain (array), agent_name.
Do NOT include any text outside the JSON object."""

async def execute_rce_agent(state: AgentState) -> dict:
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    if idx >= len(vulns):
        return {}
        
    finding = vulns[idx]
    logger.info(f"RCE Agent investigating: {finding.title}")

    context = f"Title: {finding.title}\nDescription: {finding.description}\nBlast Radius Files:\n"
    for node in finding.blast_radius:
        context += f"- {node.file_path} in {node.function_name}\n"

    try:
        from ..services.llm import create_model
        from .. import constants as cs
        
        config = settings.get_agent_config(cs.ModelRole.ANALYST)
        config.to_update_kwargs()["temperature"] = 0.0 
        model = create_model(config)
        
        agent = Agent(
            model,
            system_prompt=system_prompt,
            output_type=ThreatObject,
            retries=3,
        )
        
        result = await agent.run(context)
        threat = result.output
        threat.agent_name = "RCEAgent"
        
        return {"identified_threats": [threat]}
        
    except Exception as e:
        logger.warning(f"RCE Agent evaluation failed: {e}")
        return {}
