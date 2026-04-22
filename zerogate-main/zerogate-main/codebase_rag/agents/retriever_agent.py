"""Retriever Agent — Traverses Memgraph to map the blast radius."""

from __future__ import annotations

import mgclient
from loguru import logger

from ..api.models import AffectedNode, VulnerabilityFinding
from ..security_queries import QUERY_BANK


class RetrieverAgent:
    """Uses Graph queries to determine the blast radius of vulnerability seeds."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 7687,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password

    def _get_connection(self) -> mgclient.Connection:
        if self._username and self._password:
            conn = mgclient.connect(
                host=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
            )
        else:
            conn = mgclient.connect(host=self._host, port=self._port)
        conn.autocommit = True
        return conn

    def enrich_findings(self, findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        """Takes a list of seeds and expands their blast radius using the graph."""
        if not findings:
            return []

        logger.info(f"Retriever evaluating blast radius for {len(findings)} findings.")
        
        caller_query = next((q for q in QUERY_BANK if q.id == "caller_traversal"), None)
        callee_query = next((q for q in QUERY_BANK if q.id == "callee_traversal"), None)
        
        if not caller_query or not callee_query:
            logger.warning("Blast radius traversal queries not found in QUERY_BANK.")
            return findings

        conn = self._get_connection()
        cursor = conn.cursor()

        enriched = []
        for finding in findings:
            # Deep copy to avoid mutating the original unintentionally, or just append extra radius
            current_radius = finding.blast_radius[:]
            
            # Use the first node in blast_radius as the seed (if qualified_name is known)
            seed_qn = None
            if current_radius and current_radius[0].qualified_name:
                seed_qn = current_radius[0].qualified_name
                
            if not seed_qn:
                # If Semgrep didn't provide a qualified name, we can't easily traverse.
                # In the future, we could query the graph by file+line to resolve the QN.
                enriched.append(finding)
                continue

            try:
                # Find callers
                cursor.execute(caller_query.cypher, {"qn": seed_qn})
                for row in cursor.fetchall():
                    # Assuming row has [function, name, path, start_line, end_line]
                    fun_col, name_col, path_col, start_col, end_col = row
                    current_radius.append(
                        AffectedNode(
                            file_path=str(path_col) if path_col else "unknown",
                            function_name=str(name_col) if name_col else "unknown",
                            qualified_name=str(fun_col) if fun_col else None,
                            start_line=start_col if isinstance(start_col, int) else None,
                            end_line=end_col if isinstance(end_col, int) else None,
                        )
                    )

                # Find callees
                cursor.execute(callee_query.cypher, {"qn": seed_qn})
                for row in cursor.fetchall():
                    fun_col, name_col, path_col, start_col, end_col = row
                    current_radius.append(
                        AffectedNode(
                            file_path=str(path_col) if path_col else "unknown",
                            function_name=str(name_col) if name_col else "unknown",
                            qualified_name=str(fun_col) if fun_col else None,
                            start_line=start_col if isinstance(start_col, int) else None,
                            end_line=end_col if isinstance(end_col, int) else None,
                        )
                    )

            except Exception as e:
                logger.error(f"Error traversing graph for '{seed_qn}': {e}")
                
            finding.blast_radius = current_radius
            enriched.append(finding)

        conn.close()
        return enriched
