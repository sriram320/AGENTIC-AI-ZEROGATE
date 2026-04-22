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
    workflow.add_node("analyst_node", execute_analyst)
    workflow.add_node("patcher_node", execute_patcher)
    workflow.add_node("testgen_node", execute_testgen)
    workflow.add_node("verifier_node", execute_verifier)
    workflow.add_node("skip_node", skip_vuln)
    workflow.add_node("next_node", next_vuln)
    workflow.add_node("summarizer_node", execute_summarizer)
    
    # Define edges
    # Standard Flow: init -> (loop: analyst -> patcher/skip -> testgen -> verifier -> next -> analyst) -> summarizer -> END
    workflow.set_entry_point("init")
    workflow.add_edge("init", "analyst_node")
    
    workflow.add_conditional_edges(
        "analyst_node",
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
    def loop_or_end(state: AgentState) -> Literal["analyst_node", "summarizer_node"]:
        if state.get("current_index", 0) < len(state.get("vulnerabilities", [])):
            return "analyst_node"
        return "summarizer_node"
        
    workflow.add_conditional_edges(
        "next_node",
        loop_or_end,
        {
            "analyst_node": "analyst_node",
            "summarizer_node": "summarizer_node"
        }
    )
    
    workflow.add_edge("summarizer_node", END)
    
    return workflow.compile()
