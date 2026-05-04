"""LangGraph Orchestration for ZeroGate."""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph
from loguru import logger

from .analyst_agent import execute_analyst
from .patcher_agent import execute_patcher
from .verifier_agent import execute_verifier
from .testgen_agent import execute_testgen
from .summarizer_agent import execute_summarizer
from .state import AgentState

from .router_agent import route_to_agents
from .sqli_agent import execute_sqli_agent
from .xss_agent import execute_xss_agent
from .rce_agent import execute_rce_agent
from .dependency_agent import execute_dependency_agent
from .aggregator import execute_aggregator

# To keep it simple, the Scanner and Retriever run outside the state graph to generate
# the initial list of VulnerabilityFindings, then we pipe that list into the Graph
# to process them one by one.


def map_vulnerabilities(state: AgentState) -> dict:
    """Initializes the loop over vulnerabilities."""
    return {"current_index": 0, "all_fixes": []}


def condition_next_step(state: AgentState) -> Literal["patcher_node", "skip_node"]:
    """Routes based on whether the analyst found the bug exploitable."""
    if state.get("is_exploitable", False):
        return "patcher_node"
    return "skip_node"


def skip_vuln(state: AgentState) -> dict:
    """Skips unexploitable vulnerabilities."""
    logger.info(f"Skipping unexploitable finding at index {state.get('current_index')}")
    return {}


def next_vuln(state: AgentState) -> dict:
    """Increments the vulnerability index to process the next one."""
    idx = state.get("current_index", 0)
    return {"current_index": idx + 1}


def build_orchestrator_graph() -> StateGraph:
    """Builds the LangGraph state graph for processing vulnerability seeds."""
    
    workflow = StateGraph(AgentState)
    
    # Add nodes
    workflow.add_node("init", map_vulnerabilities)
    
    # Add parallel detection agents
    workflow.add_node("sqli_node", execute_sqli_agent)
    workflow.add_node("xss_node", execute_xss_agent)
    workflow.add_node("rce_node", execute_rce_agent)
    workflow.add_node("dep_node", execute_dependency_agent)
    workflow.add_node("analyst_node", execute_analyst)
    
    workflow.add_node("aggregator_node", execute_aggregator)
    workflow.add_node("patcher_node", execute_patcher)
    workflow.add_node("testgen_node", execute_testgen)
    workflow.add_node("verifier_node", execute_verifier)
    workflow.add_node("skip_node", skip_vuln)
    workflow.add_node("next_node", next_vuln)
    workflow.add_node("summarizer_node", execute_summarizer)
    
    # Define edges
    # Standard Flow: init -> router -> parallel_agents -> aggregator -> patcher/skip -> ...
    workflow.set_entry_point("init")
    
    # Conditional Routing from Init
    workflow.add_conditional_edges(
        "init",
        route_to_agents,
        ["sqli_node", "xss_node", "rce_node", "dep_node", "analyst_node", "skip_node"]
    )
    
    # All parallel nodes flow into Aggregator
    workflow.add_edge("sqli_node", "aggregator_node")
    workflow.add_edge("xss_node", "aggregator_node")
    workflow.add_edge("rce_node", "aggregator_node")
    workflow.add_edge("dep_node", "aggregator_node")
    workflow.add_edge("analyst_node", "aggregator_node")
    
    workflow.add_conditional_edges(
        "aggregator_node",
        condition_next_step,
        {
            "patcher_node": "patcher_node",
            "skip_node": "skip_node"
        }
    )
    
    workflow.add_edge("patcher_node", "testgen_node")
    workflow.add_edge("testgen_node", "verifier_node")
    workflow.add_edge("verifier_node", "next_node")
    workflow.add_edge("skip_node", "next_node")
    
    # Loop condition
    def loop_or_end(state: AgentState) -> list[str]:
        if state.get("current_index", 0) < len(state.get("vulnerabilities", [])):
            return route_to_agents(state)
        return ["summarizer_node"]
        
    workflow.add_conditional_edges(
        "next_node",
        loop_or_end,
        ["sqli_node", "xss_node", "rce_node", "dep_node", "analyst_node", "skip_node", "summarizer_node"]
    )
    
    workflow.add_edge("summarizer_node", END)
    
    return workflow.compile()
