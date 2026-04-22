---
description: "Semantic code search with UniXcoder embeddings in ZeroGate."
---

# Semantic Search

ZeroGate supports intent-based code search using UniXcoder embeddings. Find functions by describing what they do rather than by exact names.

## Installation

Semantic search requires the `semantic` extra:

```bash
pip install 'zerogate[semantic]'
```

## Usage

### Generate Code Embeddings

```python
from cgr import embed_code

embedding = embed_code("def authenticate(user, password): ...")
print(f"Embedding dimension: {len(embedding)}")
```

### Search by Description

In the interactive CLI, you can search semantically:

- "error handling functions"
- "authentication code"
- "database connection setup"

The system returns potential matches with similarity scores.

## How It Works

UniXcoder is a unified cross-modal pre-trained model that supports both code understanding and generation. ZeroGate uses it to create embeddings that capture the semantic meaning of code, enabling searches based on what code does rather than what it's named.
