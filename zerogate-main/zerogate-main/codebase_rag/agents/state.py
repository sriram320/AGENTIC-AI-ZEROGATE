from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from ..api.models import FixProposal, VulnerabilityFinding, ThreatObject, ThreatManifest


class AgentState(TypedDict):
    """The shared state dictionary representing the memory of the agent graph."""
    
    project_id: str
    project_path: str
    
    # Vulnerabilities to be analyzed
    vulnerabilities: list[VulnerabilityFinding]
    
    # State flags tracking the current vulnerability index
    current_index: int
    
    # Output of the analysis agent
    is_exploitable: bool
    analysis_reasoning: str
    
    # Output of detection agents (parallel merging)
    identified_threats: Annotated[list[ThreatObject], operator.add]
    threat_manifest: ThreatManifest | None
    
    # Output of the patching agent
    current_patch: FixProposal | None
    
    # Output of the verifier agent
    verification_success: bool
    verification_logs: str
    
    # Accumulate all generated fixes independently
    all_fixes: Annotated[list[FixProposal], operator.add]
    
    # Final state reporting
    executive_summary: str
