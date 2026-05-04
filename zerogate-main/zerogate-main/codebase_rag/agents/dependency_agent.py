"""Dependency & Supply Chain Agent.

Enhanced with:
- Manifest file parsing (requirements.txt, package.json, pom.xml)
- NVD CVE lookup integration
- Import reachability filtering
"""

from __future__ import annotations

from pathlib import Path

from loguru import logger
from pydantic_ai import Agent

from ..api.models import ThreatObject
from ..config import settings
from .state import AgentState

system_prompt = """You are a deterministic AST analysis engine specialising in Dependency Supply-Chain vulnerabilities. You do not write prose. You only output JSON matching the provided schema.
Follow this Chain-of-Thought Verification Template:
1. Identify the Sink: Determine the vulnerable package and CVE.
2. Trace the Source: Perform reachability analysis via Memgraph caller/callee graphs to see if the library is actually used.
3. Identify Sanitization: Check if the vulnerability is patched in a higher version or mitigated by configuration.
4. Final Verdict: VULNERABLE if the library version is known to be vulnerable (even if reachability is unknown/unprovided). CLEAN if the version is patched, recent, or explicitly mitigated.

CRITICAL: Your output MUST be valid JSON matching ThreatObject schema exactly.
Required fields: sink, source, path (array), severity (CRITICAL|HIGH|MEDIUM|LOW),
verdict (VULNERABLE|CLEAN|LOW_CONFIDENCE|UNREACHABLE), reasoning_chain (array), agent_name.
Do NOT include any text outside the JSON object."""


async def _gather_dependency_context(project_path: str) -> str:
    """Scan manifest files and perform CVE lookups to build rich context."""
    context_parts: list[str] = []
    project = Path(project_path)

    try:
        from ..parsers.dependency_parser import parse_dependencies, check_import_reachability

        # Scan for manifest files
        manifest_patterns = [
            "requirements*.txt", "package.json", "pom.xml",
            "pyproject.toml", "Cargo.toml", "go.mod", "*dependency*.txt"
        ]
        all_deps = []
        for pattern in manifest_patterns:
            for manifest in project.rglob(pattern):
                if "node_modules" in str(manifest):
                    continue
                deps = parse_dependencies(manifest)
                all_deps.extend(deps)

        if all_deps:
            context_parts.append(f"Found {len(all_deps)} dependencies:")
            for dep in all_deps[:20]:  # Limit to top 20 for context window
                reachable = check_import_reachability(project, dep.name)
                status = "IMPORTED" if reachable else "NOT_IMPORTED"
                context_parts.append(f"  - {dep.name}=={dep.version_spec} [{status}]")

            # CVE lookup for top dependencies
            try:
                from ..services.cve_lookup import lookup_cve
                for dep in all_deps[:5]:  # Limit CVE lookups
                    cves = await lookup_cve(dep.name, dep.version_spec)
                    for cve in cves:
                        context_parts.append(
                            f"  CVE: {cve.cve_id} ({cve.severity}) for {dep.name}: {cve.description[:100]}"
                        )
            except Exception as e:
                logger.debug(f"CVE lookup skipped: {e}")
        else:
            context_parts.append("No dependency manifest files found in project.")

    except Exception as e:
        logger.warning(f"Dependency context gathering failed: {e}")
        context_parts.append(f"Dependency parsing unavailable: {e}")

    return "\n".join(context_parts)


async def execute_dependency_agent(state: AgentState) -> dict:
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    if idx >= len(vulns):
        return {}
        
    finding = vulns[idx]
    logger.info(f"Dependency Agent investigating: {finding.title}")

    # Base context from finding
    context = f"Title: {finding.title}\nDescription: {finding.description}\nBlast Radius Files:\n"
    for node in finding.blast_radius:
        context += f"- {node.file_path} in {node.function_name}\n"

    # Enrich with dependency parsing and CVE data
    project_path = state.get("project_path", "")
    if project_path:
        dep_context = await _gather_dependency_context(project_path)
        context += f"\n--- Dependency Analysis ---\n{dep_context}\n"

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
        threat.agent_name = "DependencyAgent"
        
        return {"identified_threats": [threat]}
        
    except Exception as e:
        logger.warning(f"Dependency Agent evaluation failed: {e}")
        return {}
