"""Cross-Site Scripting (XSS) Agent.

Enhanced with:
- Auto-detection of framework-level XSS protections (Django, Flask/Jinja2)
- CSP header detection
- Schema enforcement for 100% validation
"""

from __future__ import annotations

from pathlib import Path

from loguru import logger
from pydantic_ai import Agent

from ..api.models import ThreatObject
from ..config import settings
from .state import AgentState

system_prompt = """You are a deterministic AST analysis engine specialising in Cross-Site Scripting (XSS). You do not write prose. You only output JSON matching the provided schema.
Follow this Chain-of-Thought Verification Template:
1. Identify the Sink: Is the payload rendered into a DOM context (innerHTML, response.write) or template response?
2. Trace the Source: Does the input come from a user-controlled request parameter?
3. Identify Sanitization: Evaluate if template autoescaping is enabled (framework_config: autoescaping = True) or if manual sanitization exists (e.g. bleach.clean).
4. Final Verdict: VULNERABLE if unsanitized data is concatenated (via +, f-string, format) directly into HTML sinks, `innerHTML`, `document.write`, or `render_template_string`, even if autoescape is supposedly enabled globally. CLEAN ONLY IF an explicit sanitizer (`bleach`, `escape()`) is wrapped around the specific variable, or if it uses `innerText`, or if global autoescaping successfully covers the exact template render call without raw bypasses.

CRITICAL: Your output MUST be valid JSON matching ThreatObject schema exactly.
Required fields: sink, source, path (array), severity (CRITICAL|HIGH|MEDIUM|LOW),
verdict (VULNERABLE|CLEAN|LOW_CONFIDENCE|UNREACHABLE), reasoning_chain (array), agent_name.
Do NOT include any text outside the JSON object."""


def detect_framework_config(project_path: str) -> dict:
    """Detect framework-level XSS protections in the project."""
    config = {
        "autoescaping": False,
        "csp_headers": False,
        "framework": "unknown",
        "sanitizers_found": [],
    }
    project = Path(project_path)

    for f in project.rglob("*.py"):
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            content_lower = content.lower()

            # Django detection (auto-escapes by default)
            if "django" in content_lower and any(
                kw in content_lower for kw in ["settings", "installed_apps", "urlpatterns"]
            ):
                config["framework"] = "django"
                config["autoescaping"] = True

            # Flask + Jinja2 detection
            if "flask" in content_lower:
                config["framework"] = "flask"
            if "jinja2" in content_lower and "autoescape" in content_lower:
                if "autoescape=true" in content_lower or "autoescape=select_autoescape" in content_lower:
                    config["autoescaping"] = True

            # CSP header detection
            if "content-security-policy" in content_lower or "secure_browser_xss_filter" in content_lower:
                config["csp_headers"] = True

            # Sanitizer detection
            for sanitizer in ["bleach", "markupsafe", "html.escape", "escape(", "sanitize"]:
                if sanitizer in content_lower:
                    config["sanitizers_found"].append(sanitizer)

        except Exception:
            continue

    # Deduplicate sanitizers
    config["sanitizers_found"] = list(set(config["sanitizers_found"]))
    return config


async def execute_xss_agent(state: AgentState) -> dict:
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    if idx >= len(vulns):
        return {}
        
    finding = vulns[idx]
    logger.info(f"XSS Agent investigating: {finding.title}")

    # Detect framework protections
    project_path = state.get("project_path", "")
    fw_config = detect_framework_config(project_path) if project_path else {}

    # Build context with framework config explicitly injected
    context = (
        f"Title: {finding.title}\n"
        f"Description: {finding.description}\n"
        f"Framework Config: autoescaping = {fw_config.get('autoescaping', False)}\n"
        f"Framework: {fw_config.get('framework', 'unknown')}\n"
        f"CSP Headers: {fw_config.get('csp_headers', False)}\n"
        f"Sanitizers Found: {fw_config.get('sanitizers_found', [])}\n"
        f"Blast Radius Files:\n"
    )
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
        threat.agent_name = "XSSAgent"
        
        return {"identified_threats": [threat]}
        
    except Exception as e:
        logger.warning(f"XSS Agent evaluation failed: {e}")
        return {}
