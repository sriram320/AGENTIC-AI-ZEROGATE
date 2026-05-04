"""Router Agent."""

from __future__ import annotations

from typing import Literal

from loguru import logger

from .state import AgentState

def route_to_agents(state: AgentState) -> list[str]:
    """Semantic domain classifier.
    Routes code blocks to relevant agents based on vulnerability category.
    Returns a list of node names to execute in parallel.
    """
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    
    if idx >= len(vulns):
        return ["skip_node"]
        
    finding = vulns[idx]
    category = finding.category.lower()
    title = finding.title.lower()
    
    routes = []
    
    if "sql" in category or "sql" in title or "injection" in title:
        routes.append("sqli_node")
    if "xss" in category or "cross-site" in title or "scripting" in title:
        routes.append("xss_node")
    if "rce" in category or "execution" in title or "command" in category:
        routes.append("rce_node")
    if "dependency" in category or "cve" in title or "supply" in category:
        routes.append("dep_node")
        
    # If no specific router matched, fallback to generic analyst
    if not routes:
        routes.append("analyst_node")
        
    logger.info(f"Router mapped finding '{finding.title}' to agents: {routes}")
    return routes
