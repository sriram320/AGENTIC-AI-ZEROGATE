"""Aggregator & Deduplication Node.

Enhanced with:
- Configurable hallucination circuit breaker with overlap scoring
- CVSS-aligned severity mapping
- Deduplication by (sink, source, verdict) signature
"""

from __future__ import annotations

from loguru import logger

from ..api.models import ThreatManifest, ThreatObject
from .state import AgentState


# --- Configurable Hallucination Circuit Breaker ---
HALLUCINATION_CONFIG = {
    "min_whitelist_overlap": 0.3,   # At least 30% of cited vars must be in whitelist
    "allow_common_terms": True,
    "common_terms": {
        "user", "input", "req", "db", "system", "request", "response",
        "query", "data", "result", "conn", "cursor", "session",
        "output", "param", "arg", "value", "config", "settings",
        "file", "path", "url", "body", "header", "cookie",
    },
    "confidence_threshold": 0.5,    # Below this = LOW_CONFIDENCE
}

# Severity to CVSS rough mapping
SEVERITY_MAP = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0}


def calculate_hallucination_score(
    threat: ThreatObject,
    whitelist: set[str],
    config: dict = HALLUCINATION_CONFIG,
) -> float:
    """Calculate a confidence score (0.0-1.0) for a threat finding.

    Higher score = more confident the finding is real (not hallucinated).
    """
    # Collect all variables cited by the agent
    cited_vars = {threat.source, threat.sink} | set(threat.path)

    # Remove common terms that should always be trusted
    if config["allow_common_terms"]:
        cited_vars -= config["common_terms"]

    # If no specific vars remain after filtering, trust the finding
    if not cited_vars:
        return 1.0

    # Calculate overlap with AST whitelist
    overlap = len(cited_vars & whitelist) / len(cited_vars)
    return overlap


async def execute_aggregator(state: AgentState) -> dict:
    """Aggregates parallel threats, applies Hallucination Circuit Breaker, deduplicates, and scores."""
    
    idx = state.get("current_index", 0)
    vulns = state.get("vulnerabilities", [])
    
    if idx >= len(vulns):
        return {}

    finding = vulns[idx]
    threats = state.get("identified_threats", [])
    logger.info(f"Aggregator processing {len(threats)} parallel agent results for {finding.title}")

    # Build the valid AST node whitelist from blast radius
    whitelist: set[str] = set()
    for node in finding.blast_radius:
        whitelist.add(node.function_name)
        if node.qualified_name:
            whitelist.add(node.qualified_name)
        # Include words from finding title and description as valid context
        for word in finding.title.split():
            whitelist.add(word)

    final_threats: list[ThreatObject] = []
    max_severity_score = 0.0

    for threat in threats:
        # 1. Hallucination Circuit Breaker (configurable scoring)
        confidence = calculate_hallucination_score(threat, whitelist)

        if confidence < HALLUCINATION_CONFIG["confidence_threshold"]:
            logger.warning(
                f"Hallucination Circuit Breaker triggered for {threat.agent_name} "
                f"(confidence={confidence:.2f}). Flagging as LOW_CONFIDENCE."
            )
            threat.verdict = "LOW_CONFIDENCE"
            threat.severity = "LOW"
            
        # 2. Deduplication by signature
        sig = f"{threat.sink}-{threat.source}-{threat.verdict}"
        if not any(f"{t.sink}-{t.source}-{t.verdict}" == sig for t in final_threats):
            final_threats.append(threat)
            
            # Update Score
            score = SEVERITY_MAP.get(threat.severity.upper(), 0.0)
            if score > max_severity_score:
                max_severity_score = score
                
    # Update analysis result based on aggregated threats
    is_exploitable = any(t.verdict == "VULNERABLE" for t in final_threats)
    
    manifest = ThreatManifest(
        threats=final_threats,
        cvss_score=max_severity_score
    )

    reasoning = f"Aggregated {len(final_threats)} valid threats. Max CVSS: {max_severity_score}."
    
    return {
        "threat_manifest": manifest,
        "is_exploitable": is_exploitable,
        "analysis_reasoning": reasoning,
        # Clear identified_threats for the next iteration loop!
        "identified_threats": [] 
    }
