"""Scanner Agent — Executes Semgrep to find vulnerability seeds."""

from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

from loguru import logger
from pydantic import BaseModel, Field

from .. import constants as cs
from ..config import settings
from ..api.models import AffectedNode, Severity, VulnerabilityFinding

class DiscoveryResponse(BaseModel):
    findings: list[VulnerabilityFinding] = Field(description="A list of newly discovered vulnerabilities.", default_factory=list)


class ScannerAgent:
    """Executes Semgrep to detect initial vulnerability seeds."""

    def __init__(self, project_path: str = ".") -> None:
        self.project_path = Path(project_path)

    def _map_severity(self, semgrep_severity: str) -> Severity:
        semgrep_severity = semgrep_severity.upper()
        if semgrep_severity == "ERROR":
            return Severity.HIGH
        elif semgrep_severity == "WARNING":
            return Severity.MEDIUM
        return Severity.LOW

    def run_scan(self, config: str = "p/default") -> list[VulnerabilityFinding]:
        """Runs Semgrep and returns a list of vulnerability findings."""
        logger.info(f"Running Semgrep on {self.project_path} with config={config}")
        
        import os
        import sys
        semgrep_path = os.path.join(os.path.dirname(sys.executable), "semgrep")
        # Try adding .exe if on Windows and it doesn't exist as is
        if os.name == "nt" and not os.path.exists(semgrep_path) and os.path.exists(semgrep_path + ".exe"):
            semgrep_path += ".exe"
            
        cmd = [
            sys.executable,
            semgrep_path,
            "scan",
            "--config", config,
            "--json",
            "--quiet",
            str(self.project_path)
        ]
        
        try:
            is_windows = os.name == "nt"
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                check=False,
                shell=is_windows
            )
            
            # Remove any non-JSON noise from start (like shebang warnings)
            output = result.stdout.strip()
            if not output.startswith("{"):
                start_id = output.find("{")
                if start_id != -1:
                    output = output[start_id:]
                else:
                    logger.error("Semgrep output does not contain JSON.")
                    return []
            
            data = json.loads(output)
            findings: list[VulnerabilityFinding] = []
            
            for match in data.get("results", []):
                finding_id = uuid.uuid4().hex[:12]
                file_path = match.get("path", "")
                
                # Relativize path if possible
                try:
                    rel_path = Path(file_path).relative_to(self.project_path)
                    file_path = str(rel_path)
                except ValueError:
                    pass
                    
                start_line = match.get("start", {}).get("line")
                end_line = match.get("end", {}).get("line")
                
                extra = match.get("extra", {})
                message = extra.get("message", "Semgrep Finding")
                semgrep_severity = extra.get("severity", "INFO")
                severity = self._map_severity(semgrep_severity)
                
                # Extract function or class name if provided in metadata, otherwise unknown
                # Since Semgrep doesn't easily expose the function name without AST parsing,
                # we set it to 'unknown' and the retriever agent will help resolve it.
                function_name = "unknown"
                
                blast_radius = [
                    AffectedNode(
                        file_path=file_path,
                        function_name=function_name,
                        start_line=start_line,
                        end_line=end_line,
                    )
                ]
                
                finding = VulnerabilityFinding(
                    finding_id=finding_id,
                    title=f"Semgrep: {match.get('check_id', 'Finding')}",
                    severity=severity,
                    category="Semgrep Rule",
                    description=message,
                    blast_radius=blast_radius,
                )
                findings.append(finding)
                
            logger.success(f"Semgrep found {len(findings)} vulnerability seeds.")
            return findings
            
        except FileNotFoundError:
            logger.error("Semgrep is not installed or not in PATH. Please install semgrep.")
            return []
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep JSON output.")
            return []
        except Exception as e:
            logger.error(f"Unexpected error running Semgrep: {e}")
            return []

    async def run_discovery_async(self, semgrep_findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        """Uses the DISCOVERY agent to analyze files flagged by Semgrep for deeper logic flaws."""
        if not semgrep_findings:
            return []
            
        logger.info("Initializing LLM Discovery Agent for deeper context inspection.")
        
        # Get unique files flagged by Semgrep
        flagged_files = {node.file_path for finding in semgrep_findings for node in finding.blast_radius}
        
        new_findings: list[VulnerabilityFinding] = []
        
        try:
            from pydantic_ai import Agent
            from ..services.llm import create_model
            
            config = settings.get_agent_config(cs.ModelRole.DISCOVERY)
            model = create_model(config)
            agent = Agent(
                model,
                output_type=DiscoveryResponse,
                system_prompt=(
                    "You are the Discovery Agent. You analyze raw source files that were "
                    "flagged for superficial syntax vulnerabilities, and look for deeper "
                    "contextual logic flaws that the static analysis engine missed."
                ),
            )
            
            for file_path in flagged_files:
                full_path = self.project_path / file_path
                if not full_path.exists():
                    continue
                    
                code = full_path.read_text(encoding="utf-8")
                prompt = (
                    f"Review the following file ({file_path}) for severe logic vulnerabilities "
                    "(e.g., Auth Bypasses, Insecure Direct Object References, logic flaws).\n"
                    "If you find none, return an empty array.\n"
                    f"```\n{code}\n```"
                )
                
                result = await agent.run(prompt)
                
                # Append file path forcefully so standard agent schemas hold
                for finding in result.output.findings:
                    # Fix ID and file paths
                    finding.finding_id = uuid.uuid4().hex[:12]
                    for node in finding.blast_radius:
                        node.file_path = file_path
                    new_findings.append(finding)
            
            if new_findings:
                logger.success(f"Discovery Agent found {len(new_findings)} hidden logic flaws.")
            return new_findings
            
        except Exception as e:
            logger.error(f"Discovery Agent failed: {e}")
            return []
