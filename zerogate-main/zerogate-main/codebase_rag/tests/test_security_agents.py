"""Unit Tests for Multi-Agent Security Detection System.
Includes Layer 1 (Isolation) and Layer 2 (Reasoning) tests as per project report.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import ValidationError

from codebase_rag.api.models import ThreatObject, ThreatManifest, Severity, VulnerabilityFinding, AffectedNode
from codebase_rag.agents.state import AgentState
from codebase_rag.agents.sqli_agent import execute_sqli_agent
from codebase_rag.agents.xss_agent import execute_xss_agent
from codebase_rag.agents.aggregator import execute_aggregator
from codebase_rag.services.llm import run_agent_with_fallback

# --- Layer 1: Tool-Call & Schema Isolation Tests ---

def test_threat_object_schema_validation():
    """Test Pydantic validator schemas for ThreatObject."""
    # Valid payload
    valid_data = {
        "sink": "cursor.execute",
        "source": "req.query.id",
        "path": ["req.query.id", "user_id", "cursor.execute"],
        "severity": Severity.CRITICAL,
        "verdict": "VULNERABLE",
        "reasoning_chain": ["1. Sink is cursor.execute", "2. Source is req.query.id"],
        "agent_name": "SQLiAgent"
    }
    threat = ThreatObject(**valid_data)
    assert threat.sink == "cursor.execute"
    assert threat.verdict == "VULNERABLE"

    # Invalid verdict should raise ValidationError
    invalid_data = valid_data.copy()
    invalid_data["verdict"] = "MAYBE"
    with pytest.raises(ValidationError):
        ThreatObject(**invalid_data)


@pytest.mark.asyncio
async def test_run_agent_with_fallback_success():
    """Test tenacity wrapper succeeds on first try."""
    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value="Success")
    mock_config = MagicMock()
    
    result = await run_agent_with_fallback(mock_agent, "test prompt", mock_config)
    assert result == "Success"
    assert mock_agent.run.call_count == 1


@pytest.mark.asyncio
async def test_aggregator_hallucination_circuit_breaker():
    """Test that Aggregator flags unverified variables as LOW_CONFIDENCE."""
    
    # Setup mock state with a threat citing an unknown variable
    node = AffectedNode(file_path="app.py", function_name="get_user")
    finding = VulnerabilityFinding(
        finding_id="1",
        title="SQL Injection",
        severity=Severity.HIGH,
        category="SQL",
        description="SQLi found",
        blast_radius=[node]
    )
    
    threat = ThreatObject(
        sink="execute",
        source="hallucinated_var", # Not in blast radius
        path=["hallucinated_var", "execute"],
        severity=Severity.CRITICAL,
        verdict="VULNERABLE",
        reasoning_chain=["hallucinated_var flows to execute"],
        agent_name="SQLiAgent"
    )
    
    state: AgentState = {
        "vulnerabilities": [finding],
        "current_index": 0,
        "identified_threats": [threat],
        "project_id": "test",
        "project_path": "/test",
        "is_exploitable": False,
        "analysis_reasoning": "",
        "current_patch": None,
        "verification_success": False,
        "verification_logs": "",
        "all_fixes": [],
        "threat_manifest": None
    }
    
    result = await execute_aggregator(state)
    manifest: ThreatManifest = result["threat_manifest"]
    
    assert len(manifest.threats) == 1
    # Circuit breaker should have downgraded this
    assert manifest.threats[0].verdict == "LOW_CONFIDENCE"
    assert manifest.threats[0].severity == "LOW"


# --- Layer 2: Agent Reasoning Tests (Mocked LLM) ---

@pytest.fixture
def mock_vuln_state():
    node = AffectedNode(file_path="auth.py", function_name="login", start_line=10, end_line=15)
    finding = VulnerabilityFinding(
        finding_id="1",
        title="SQL Injection",
        severity=Severity.HIGH,
        category="SQL",
        description="Potential SQLi",
        blast_radius=[node]
    )
    return {
        "vulnerabilities": [finding],
        "current_index": 0,
        "identified_threats": [],
        "project_id": "test",
        "project_path": "/test"
    }


@pytest.mark.asyncio
@patch("codebase_rag.agents.sqli_agent.Agent")
async def test_sqli_agent_positive_sample(MockAgent, mock_vuln_state):
    """Test SQLi Agent correctly identifies a VULNERABLE sample."""
    
    # Mock LLM returning a positive ThreatObject
    mock_result = MagicMock()
    mock_result.data = ThreatObject(
        sink="cursor.execute",
        source="req.query",
        path=["req.query", "query", "cursor.execute"],
        severity=Severity.CRITICAL,
        verdict="VULNERABLE",
        reasoning_chain=["Found sink cursor.execute", "Traced to req.query"],
        agent_name="SQLiAgent"
    )
    
    mock_agent_instance = MagicMock()
    mock_agent_instance.run = AsyncMock(return_value=mock_result)
    MockAgent.return_value = mock_agent_instance
    
    result = await execute_sqli_agent(mock_vuln_state)
    
    assert "identified_threats" in result
    threat = result["identified_threats"][0]
    assert threat.verdict == "VULNERABLE"
    assert threat.agent_name == "SQLiAgent"


@pytest.mark.asyncio
@patch("codebase_rag.agents.xss_agent.Agent")
async def test_xss_agent_negative_sample(MockAgent, mock_vuln_state):
    """Test XSS Agent correctly identifies a CLEAN sample (autoescaping=True)."""
    
    # Mock LLM returning a negative ThreatObject
    mock_result = MagicMock()
    mock_result.data = ThreatObject(
        sink="render_template",
        source="user_input",
        path=["user_input", "render_template"],
        severity=Severity.LOW,
        verdict="CLEAN",
        reasoning_chain=["Found sink", "Input is sanitized because autoescaping=True"],
        agent_name="XSSAgent"
    )
    
    mock_agent_instance = MagicMock()
    mock_agent_instance.run = AsyncMock(return_value=mock_result)
    MockAgent.return_value = mock_agent_instance
    
    result = await execute_xss_agent(mock_vuln_state)
    
    assert "identified_threats" in result
    threat = result["identified_threats"][0]
    assert threat.verdict == "CLEAN"
    assert "autoescaping=True" in threat.reasoning_chain[1]


# --- Layer 3: Pipeline Integration Tests ---

@pytest.mark.asyncio
async def test_langgraph_pipeline_integration():
    """Test full LangGraph pipeline initialization and routing."""
    from codebase_rag.agents.graph import build_orchestrator_graph
    
    workflow = build_orchestrator_graph()
    
    # Just testing the compilation and basic structure works
    assert workflow is not None
    
    node = AffectedNode(file_path="app.py", function_name="eval_input")
    finding = VulnerabilityFinding(
        finding_id="rce-1",
        title="Remote Code Execution",
        severity=Severity.CRITICAL,
        category="RCE",
        description="os.system call",
        blast_radius=[node]
    )
    
    state: AgentState = {
        "vulnerabilities": [finding],
        "current_index": 0,
        "identified_threats": [],
        "project_id": "test",
        "project_path": "/test",
        "is_exploitable": False,
        "analysis_reasoning": "",
        "current_patch": None,
        "verification_success": False,
        "verification_logs": "",
        "all_fixes": [],
        "threat_manifest": None
    }
    
    # We can invoke the graph up to a certain point or just test the router
    from codebase_rag.agents.router_agent import route_to_agents
    routes = route_to_agents(state)
    assert "rce_node" in routes
