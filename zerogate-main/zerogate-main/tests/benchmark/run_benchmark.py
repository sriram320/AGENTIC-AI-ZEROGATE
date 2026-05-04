"""Performance Benchmark Suite for ZeroGate Security Agents.

Runs each agent against a labeled dataset of 120 samples and computes:
- Accuracy, Precision, Recall, F1 Score
- Average Latency per agent invocation
- Confusion matrix (TP, FP, TN, FN)

Usage:
    python -m tests.benchmark.run_benchmark
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Import agents and models to test
from codebase_rag.agents.sqli_agent import execute_sqli_agent
from codebase_rag.agents.xss_agent import execute_xss_agent
from codebase_rag.agents.rce_agent import execute_rce_agent
from codebase_rag.agents.dependency_agent import execute_dependency_agent
from codebase_rag.api.models import VulnerabilityFinding, Severity, AffectedNode
from codebase_rag.agents.state import AgentState

# Benchmark results container
@dataclass
class AgentBenchmarkResult:
    """Stores confusion matrix + latency for a single agent."""
    agent_name: str
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    latencies: list[float] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / max(self.total, 1)

    @property
    def precision(self) -> float:
        return self.tp / max(self.tp + self.fp, 1)

    @property
    def recall(self) -> float:
        return self.tp / max(self.tp + self.fn, 1)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(p + r, 1e-9)

    @property
    def avg_latency_ms(self) -> float:
        return (sum(self.latencies) / max(len(self.latencies), 1)) * 1000

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_name,
            "total_samples": self.total,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "accuracy": round(self.accuracy * 100, 1),
            "precision": round(self.precision * 100, 1),
            "recall": round(self.recall * 100, 1),
            "f1": round(self.f1 * 100, 1),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
        }


@dataclass
class BenchmarkSample:
    """A single labeled sample from ground_truth.json."""
    id: str
    file: str
    category: str
    expected_verdict: str
    expected_severity: str
    description: str


def load_ground_truth(path: Path) -> list[BenchmarkSample]:
    """Load labeled samples from ground_truth.json."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return [BenchmarkSample(**s) for s in data.get("samples", [])]


def compute_confusion(predicted: str, expected: str) -> tuple[int, int, int, int]:
    """Returns (tp, fp, tn, fn) increments."""
    is_vuln_predicted = predicted == "VULNERABLE"
    is_vuln_expected = expected == "VULNERABLE"

    if is_vuln_predicted and is_vuln_expected:
        return (1, 0, 0, 0)
    if is_vuln_predicted and not is_vuln_expected:
        return (0, 1, 0, 0)
    if not is_vuln_predicted and not is_vuln_expected:
        return (0, 0, 1, 0)
    return (0, 0, 0, 1)


def format_report(results: list[AgentBenchmarkResult]) -> str:
    """Format benchmark results as a markdown table."""
    lines = [
        "# ZeroGate Performance Benchmark Report",
        "",
        "| Agent | Samples | Accuracy | Precision | Recall | F1 | Avg Latency |",
        "|-------|---------|----------|-----------|--------|-----|-------------|",
    ]
    for r in results:
        d = r.to_dict()
        lines.append(
            f"| {d['agent']} | {d['total_samples']} | {d['accuracy']}% "
            f"| {d['precision']}% | {d['recall']}% | {d['f1']}% "
            f"| {d['avg_latency_ms']}ms |"
        )
    lines.append("")
    lines.append("## Confusion Matrices")
    for r in results:
        lines.append(f"\n### {r.agent_name}")
        lines.append(f"- TP: {r.tp}  FP: {r.fp}")
        lines.append(f"- FN: {r.fn}  TN: {r.tn}")
    return "\n".join(lines)


# --- Example ground_truth.json template ---
GROUND_TRUTH_TEMPLATE = {
    "samples": [
        # SQLi Positive Samples
        {"id": "sqli_pos_01", "file": "samples/sqli/positive/concat_query.py",
         "category": "SQL Injection", "expected_verdict": "VULNERABLE",
         "expected_severity": "CRITICAL", "description": "String concat into cursor.execute"},
        {"id": "sqli_pos_02", "file": "samples/sqli/positive/fstring_query.py",
         "category": "SQL Injection", "expected_verdict": "VULNERABLE",
         "expected_severity": "CRITICAL", "description": "f-string into cursor.execute"},
        {"id": "sqli_pos_03", "file": "samples/sqli/positive/format_query.py",
         "category": "SQL Injection", "expected_verdict": "VULNERABLE",
         "expected_severity": "CRITICAL", "description": ".format() into raw SQL"},
        # SQLi Negative Samples
        {"id": "sqli_neg_01", "file": "samples/sqli/negative/parameterized.py",
         "category": "SQL Injection", "expected_verdict": "CLEAN",
         "expected_severity": "LOW", "description": "Parameterized query with ?"},
        {"id": "sqli_neg_02", "file": "samples/sqli/negative/orm_safe.py",
         "category": "SQL Injection", "expected_verdict": "CLEAN",
         "expected_severity": "LOW", "description": "Django ORM filter()"},
        # XSS Positive Samples
        {"id": "xss_pos_01", "file": "samples/xss/positive/raw_render.py",
         "category": "XSS", "expected_verdict": "VULNERABLE",
         "expected_severity": "HIGH", "description": "Unsafe innerHTML injection"},
        # XSS Negative Samples
        {"id": "xss_neg_01", "file": "samples/xss/negative/autoescape.py",
         "category": "XSS", "expected_verdict": "CLEAN",
         "expected_severity": "LOW", "description": "Jinja2 autoescape=True"},
        # RCE Positive Samples
        {"id": "rce_pos_01", "file": "samples/rce/positive/os_system.py",
         "category": "RCE", "expected_verdict": "VULNERABLE",
         "expected_severity": "CRITICAL", "description": "os.system with user input"},
        # RCE Negative Samples
        {"id": "rce_neg_01", "file": "samples/rce/negative/allowlist.py",
         "category": "RCE", "expected_verdict": "CLEAN",
         "expected_severity": "LOW", "description": "Allowlist validation before exec"},
        # Dependency Positive Samples
        {"id": "dep_pos_01", "file": "samples/dependency/positive/log4j.txt",
         "category": "Dependency", "expected_verdict": "VULNERABLE",
         "expected_severity": "CRITICAL", "description": "log4j 2.14.1 with CVE-2021-44228"},
        # Dependency Negative Samples
        {"id": "dep_neg_01", "file": "samples/dependency/negative/patched.txt",
         "category": "Dependency", "expected_verdict": "CLEAN",
         "expected_severity": "LOW", "description": "Patched version of flask"},
    ]
}


def generate_ground_truth_template(output_path: Path) -> None:
    """Generate a template ground_truth.json and dummy files for testing."""
    base_dir = output_path.parent
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Write ground_truth.json
    output_path.write_text(json.dumps(GROUND_TRUTH_TEMPLATE, indent=2), encoding="utf-8")
    
    # 2. Create actual dummy files for the benchmark to read
    files_to_create = {
        "samples/sqli/positive/concat_query.py": "query = 'SELECT * FROM users WHERE id = ' + req.query.id\ncursor.execute(query)",
        "samples/sqli/positive/fstring_query.py": "query = f'SELECT * FROM users WHERE id = {req.query.id}'\ncursor.execute(query)",
        "samples/sqli/positive/format_query.py": "query = 'SELECT * FROM users WHERE id = {}'.format(req.query.id)\ncursor.execute(query)",
        "samples/sqli/negative/parameterized.py": "query = 'SELECT * FROM users WHERE id = ?'\ncursor.execute(query, (req.query.id,))",
        "samples/sqli/negative/orm_safe.py": "user = User.objects.filter(id=req.query.id).first()",
        "samples/xss/positive/raw_render.py": "return '<div>' + req.query.name + '</div>' # Renders directly",
        "samples/xss/negative/autoescape.py": "# Framework Config: autoescaping = True\nreturn render_template('profile.html', name=req.query.name)",
        "samples/rce/positive/os_system.py": "import os\nos.system('ping ' + req.query.ip)",
        "samples/rce/negative/allowlist.py": "import os\nif req.query.ip in ['127.0.0.1']: os.system('ping ' + req.query.ip)",
        "samples/dependency/positive/log4j.txt": "log4j:log4j-core:2.14.1",
        "samples/dependency/negative/patched.txt": "flask==3.0.0",
    }
    
    for rel_path, content in files_to_create.items():
        file_path = base_dir / rel_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")

    print(f"Template and dummy files generated in {base_dir}")


async def run_single_agent(agent_fn: Callable, sample: BenchmarkSample, base_dir: Path) -> tuple[str, float]:
    """Execute a single agent on a sample file and measure latency."""
    file_path = base_dir / sample.file
    source_code = file_path.read_text(encoding="utf-8") if file_path.exists() else "Missing file"
    
    # Create mock state
    node = AffectedNode(file_path=str(file_path), function_name="test_func")
    finding = VulnerabilityFinding(
        finding_id=sample.id,
        title=sample.category,
        severity=Severity.HIGH,
        category=sample.category,
        description=f"Source code context:\n{source_code}",
        blast_radius=[node]
    )
    
    state: AgentState = {
        "vulnerabilities": [finding],
        "current_index": 0,
        "identified_threats": [],
        "project_id": "benchmark",
        "project_path": str(base_dir),
        "is_exploitable": False,
        "analysis_reasoning": "",
        "current_patch": None,
        "verification_success": False,
        "verification_logs": "",
        "all_fixes": [],
        "threat_manifest": None,
        "executive_summary": ""
    }

    start = time.monotonic()
    result = await agent_fn(state)
    elapsed = time.monotonic() - start

    threats = result.get("identified_threats", [])
    predicted = threats[0].verdict if threats else "CLEAN"
    
    # Map LOW_CONFIDENCE or UNREACHABLE to CLEAN for binary classification
    if predicted in ["LOW_CONFIDENCE", "UNREACHABLE"]:
        predicted = "CLEAN"
        
    return predicted, elapsed


async def run_benchmark(samples: list[BenchmarkSample], base_dir: Path):
    """Run the full benchmark suite."""
    print(f"Starting benchmark on {len(samples)} samples...")
    
    agents = {
        "SQL Injection": ("SQLiAgent", execute_sqli_agent),
        "XSS": ("XSSAgent", execute_xss_agent),
        "RCE": ("RCEAgent", execute_rce_agent),
        "Dependency": ("DependencyAgent", execute_dependency_agent),
    }
    
    results_map = {}
    
    for sample in samples:
        if sample.category not in agents:
            continue
            
        agent_name, agent_fn = agents[sample.category]
        if agent_name not in results_map:
            results_map[agent_name] = AgentBenchmarkResult(agent_name=agent_name)
            
        print(f"Testing {sample.id} with {agent_name}...")
        predicted, latency = await run_single_agent(agent_fn, sample, base_dir)
        
        # Update metrics
        r = results_map[agent_name]
        r.latencies.append(latency)
        tp, fp, tn, fn = compute_confusion(predicted, sample.expected_verdict)
        r.tp += tp; r.fp += fp; r.tn += tn; r.fn += fn
        
    # Generate Report
    final_results = list(results_map.values())
    report_md = format_report(final_results)
    
    report_path = base_dir / "benchmark_results.md"
    report_path.write_text(report_md, encoding="utf-8")
    
    print("\nBenchmark Complete! Report generated:")
    print("-" * 50)
    print(report_md)
    print("-" * 50)
    print(f"Saved to: {report_path}")


if __name__ == "__main__":
    benchmark_dir = Path(__file__).parent
    gt_path = benchmark_dir / "ground_truth.json"

    if not gt_path.exists():
        print("No ground_truth.json found. Generating template...")
        generate_ground_truth_template(gt_path)
        print("Run the script again to execute the benchmark.")
    else:
        samples = load_ground_truth(gt_path)
        asyncio.run(run_benchmark(samples, benchmark_dir))
