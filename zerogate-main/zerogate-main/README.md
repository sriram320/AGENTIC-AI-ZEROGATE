# ZeroGate: The Autonomous Security Graph

[![Build Passing](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/krrishitejas/zerogate/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Introduction

ZeroGate is an autonomous, local‑first security graph engine designed for red‑teamers and security researchers.  Instead of merely searching code, ZeroGate constructs a dynamic graph of the target codebase, applies graph‑based retrieval (Graph‑RAG), and intelligently maps logical paths to potential vulnerabilities. It can:

- **Map control flow** across large codebases without requiring a full compilation or interpreter.
- **Detect logical flaws** such as insecure data flows, privilege escalations, and resource leaks.
- **Suggest mitigations** by highlighting vulnerable code snippets and offering patch templates.
- **Operate offline** – all analysis runs locally, preserving confidentiality.

Whether you’re performing a quick penetration test, a full code‑review engagement, or building automated security tooling, ZeroGate gives you the graph‑centric view needed to uncover hard‑to‑find bugs.

---

## Getting Started

```bash
# Clone the repo (or use the released package)
git clone https://github.com/krrishitejas/zerogate.git
cd zerogate

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e .

# Optional: spin up the local database
docker compose up -d memgraph

# Run the CLI
zerogate --help
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Graph Construction** | Builds a control‑flow / data‑flow graph from source code. |
| **Graph‑RAG Engine** | Retrieves relevant code paths and patterns using vector similarity. |
| **Vulnerability Detection** | Applies static analysis rules over the graph to find common exploitation patterns. |
| **Patch Generation** | Generates diff patches or code snippets that remediate identified issues. |
| **Local‑First** | All processing is done on your machine; no external APIs are required. |
| **Extensible** | Add custom rule sets or integrate with other security tools via the plugin API. |

---

## Quick Example

```python
from zerogate import ZeroGate

# Load a local project
zg = ZeroGate(project_path="path/to/target")
zg.build_graph()

# Find potential command injection points
issues = zg.find_vulnerabilities(pattern="CommandInjection")
for issue in issues:
    print(issue)
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

ZeroGate is released under the [MIT License](LICENSE).

> **Note**: ZeroGate is built on top of the open‑source foundation originally released by krrishitejas as "ZeroGate". The core architecture remains the same, but the focus, naming, and documentation have been shifted to reflect its security‑oriented mission.
