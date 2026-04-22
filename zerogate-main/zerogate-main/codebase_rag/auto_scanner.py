"""Auto-Hunter Vulnerability Engine — Autonomous security scanning."""

from __future__ import annotations

import asyncio
import difflib
import uuid
from datetime import datetime
from pathlib import Path

import mgclient
from loguru import logger

from .api.models import (
    AffectedNode,
    FixProposal,
    ReportSummary,
    Severity,
    VulnerabilityFinding,
    VulnerabilityReport,
)
from .config import ModelConfig
from .security_queries import QUERY_BANK, SecurityQuery
from .agents.scanner_agent import ScannerAgent
from .agents.retriever_agent import RetrieverAgent


class AutoScanner:
    """
    Executes the Security Query Bank against the Memgraph knowledge graph
    and enriches findings using the configured LLM.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        project_path: str = ".",
        orchestrator_config: ModelConfig | None = None,
        max_concurrent: int = 5,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._project_path = Path(project_path)
        self._orchestrator_config = orchestrator_config
        self._semaphore = asyncio.Semaphore(max_concurrent)

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

    async def run_full_scan(self, project_id: str) -> VulnerabilityReport:
        """Execute all security queries and compile the vulnerability report."""
        logger.info(f"Starting Auto-Hunter scan for project {project_id}")

        findings: list[VulnerabilityFinding] = []

        # 1. Run Semgrep via ScannerAgent
        scanner_agent = ScannerAgent(str(self._project_path))
        semgrep_results = await asyncio.to_thread(scanner_agent.run_scan)
        findings.extend(semgrep_results)
        
        # 1.5 Run LLM Discovery Agent over Semgrep flags
        discovery_results = await scanner_agent.run_discovery_async(semgrep_results)
        findings.extend(discovery_results)

        # 2. Run graph-based security queries
        # Filter out traversal queries from being executed as top-level scans
        scan_queries = [q for q in QUERY_BANK if q.category != "Blast Radius"]
        tasks = [self._execute_security_query(query) for query in scan_queries]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Security query '{scan_queries[i].id}' failed: {result}")
                continue
            if isinstance(result, list):
                findings.extend(result)

        # 3. Traversal via RetrieverAgent to enrich blast radius
        retriever_agent = RetrieverAgent(
            host=self._host,
            port=self._port,
            username=self._username,
            password=self._password,
        )
        findings = await asyncio.to_thread(retriever_agent.enrich_findings, findings)

        # Build summary
        summary = ReportSummary(
            total=len(findings),
            critical=sum(1 for f in findings if f.severity == Severity.CRITICAL),
            high=sum(1 for f in findings if f.severity == Severity.HIGH),
            medium=sum(1 for f in findings if f.severity == Severity.MEDIUM),
            low=sum(1 for f in findings if f.severity == Severity.LOW),
        )

        report = VulnerabilityReport(
            project_id=project_id,
            scan_timestamp=datetime.now().isoformat(),
            findings=findings,
            summary=summary,
        )

        logger.success(
            f"Auto-Hunter scan complete: {summary.total} findings "
            f"({summary.critical} critical, {summary.high} high, "
            f"{summary.medium} medium, {summary.low} low)"
        )
        return report

    async def _execute_security_query(
        self, query: SecurityQuery
    ) -> list[VulnerabilityFinding]:
        """Execute a single security query against Memgraph."""
        async with self._semaphore:
            return await asyncio.to_thread(self._run_query_sync, query)

    def _run_query_sync(self, query: SecurityQuery) -> list[VulnerabilityFinding]:
        """Synchronous query execution in a thread."""
        findings: list[VulnerabilityFinding] = []

        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute(query.cypher)

            # Extract column names properly, handling both tuples and mgclient.Column objects
            columns = []
            for desc in cursor.description or []:
                if isinstance(desc, tuple):
                    columns.append(desc[0])
                elif hasattr(desc, "name"):
                    columns.append(desc.name)
                else:
                    columns.append(str(desc))

            rows = cursor.fetchall()
            conn.close()

            if not rows:
                return findings

            for row in rows:
                row_dict = dict(zip(columns, row))
                finding_id = uuid.uuid4().hex[:12]

                func_name = row_dict.get("name", row_dict.get("caller_name", "unknown"))
                qualified = row_dict.get(
                    "function",
                    row_dict.get("qualified_name", row_dict.get("caller", "")),
                )
                file_path = self._resolve_file_path(qualified)

                blast_radius = [
                    AffectedNode(
                        file_path=file_path,
                        function_name=str(func_name),
                        qualified_name=str(qualified) if qualified else None,
                        start_line=row_dict.get("start_line"),
                        end_line=row_dict.get("end_line"),
                    )
                ]

                # For call-chain queries, add the callee too
                if "callee" in row_dict:
                    callee_path = self._resolve_file_path(row_dict.get("callee", ""))
                    blast_radius.append(
                        AffectedNode(
                            file_path=callee_path,
                            function_name=str(row_dict.get("callee_name", "unknown")),
                            qualified_name=str(row_dict.get("callee", "")),
                        )
                    )

                findings.append(
                    VulnerabilityFinding(
                        finding_id=finding_id,
                        title=f"{query.title}: {func_name}",
                        severity=Severity(query.severity),
                        category=query.category,
                        description=query.description,
                        blast_radius=blast_radius,
                    )
                )

        except Exception as e:
            logger.error(f"Query '{query.id}' execution error: {e}")

        return findings

    def _resolve_file_path(self, qualified_name: str) -> str:
        """Attempt to convert a qualified name to a file path."""
        if not qualified_name:
            return "unknown"
        
        parts = qualified_name.split(".")
        
        # 1. Try resolving parts directly
        for i in range(len(parts), 0, -1):
            candidate = "/".join(parts[:i]) + ".py"
            if (self._project_path / candidate).exists():
                return candidate
                
        # 2. Try stripping the first part (often the project root folder name)
        if len(parts) > 1:
            sub_parts = parts[1:]
            for i in range(len(sub_parts), 0, -1):
                candidate = "/".join(sub_parts[:i]) + ".py"
                if (self._project_path / candidate).exists():
                    return candidate
        
        # 3. Try finding by matching part of the name
        sub_parts = parts[1:] if len(parts) > 1 else parts
        for part in sub_parts:
            for file in self._project_path.rglob("*.py"):
                if part.lower() in file.name.lower():
                    return str(file.relative_to(self._project_path)).replace("\\", "/")

        # 4. Fallback: Search for any .py file if it's a very simple project
        all_py = list(self._project_path.glob("*.py"))
        if len(all_py) == 1:
            return all_py[0].name

        return "app.py" if (self._project_path / "app.py").exists() else (parts[0] + ".py" if parts else "unknown")

    async def generate_fix(self, finding: VulnerabilityFinding) -> FixProposal:
        """Generate an AI-powered fix for a vulnerability finding."""
        if not finding.blast_radius:
            raise ValueError("Finding has no blast radius — cannot generate fix.")

        target = finding.blast_radius[0]
        file_path = target.file_path
        full_path = self._project_path / file_path

        # Read the source code
        if not full_path.exists():
            raise FileNotFoundError(f"Source file not found: {full_path}")

        source_lines = full_path.read_text(encoding="utf-8").splitlines(keepends=True)

        # Extract the relevant code block
        start = (target.start_line or 1) - 1
        end = target.end_line or len(source_lines)
        original_code = "".join(source_lines[start:end])

        # Generate fix using LLM
        patched_code = await self._generate_fix_with_llm(original_code, finding)

        # Create unified diff
        diff = difflib.unified_diff(
            original_code.splitlines(keepends=True),
            patched_code.splitlines(keepends=True),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        unified_diff = "".join(diff)

        return FixProposal(
            finding_id=finding.finding_id,
            original_code=original_code,
            patched_code=patched_code,
            unified_diff=unified_diff,
            explanation=(
                f"Fixed {finding.category} vulnerability in "
                f"{target.function_name}. {finding.description}"
            ),
            file_path=file_path,
            function_name=target.function_name,
        )

    async def _generate_fix_with_llm(
        self,
        original_code: str,
        finding: VulnerabilityFinding,
    ) -> str:
        """Call the LLM to generate a security fix."""
        try:
            from pydantic_ai import Agent

            from .services.llm import create_model

            model = create_model(self._orchestrator_config)

            agent = Agent(
                model,
                system_prompt=(
                    "You are a senior security engineer. You will be given "
                    "vulnerable source code and a description of the "
                    "vulnerability. Return ONLY the fixed code with no "
                    "explanation, no markdown fences, just the corrected "
                    "source code. Preserve the original formatting and "
                    "indentation."
                ),
            )

            prompt = (
                f"Vulnerability: {finding.category} — {finding.title}\n"
                f"Description: {finding.description}\n\n"
                f"Vulnerable code:\n```\n{original_code}\n```\n\n"
                "Return the fixed code only:"
            )

            result = await agent.run(prompt)
            return result.output if hasattr(result, "output") else str(result.data)

        except Exception as e:
            logger.warning(f"LLM fix generation failed: {e}, returning original")
            return original_code
