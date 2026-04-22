#!/usr/bin/env bash
# rebrand_zerogate.sh – Rebrand "ZeroGate" to "ZeroGate"
set -euo pipefail

OLD_BASE="zerogate"
NEW_BASE="zerogate"

# Determine sed inline flag (BSD vs GNU)
if [[ "$(uname)" == "Darwin" ]]; then
  SED_IN="-i ''"
else
  SED_IN="-i"
fi

# 1. Rename directories
find . -type d -name "*${OLD_BASE}*" -print0 | while IFS= read -r -d '' dir; do
  new_dir="${dir/${OLD_BASE}/${NEW_BASE}}"
  if [[ "$dir" != "$new_dir" ]]; then
    echo "Renaming dir: $dir -> $new_dir"
    mv "$dir" "$new_dir"
  fi
done

# 2. Rename files
find . -type f -name "*${OLD_BASE}*" -print0 | while IFS= read -r -d '' file; do
  new_file="${file/${OLD_BASE}/${NEW_BASE}}"
  if [[ "$file" != "$new_file" ]]; then
    echo "Renaming file: $file -> $new_file"
    mv "$file" "$new_file"
  fi
done

# 3. In‑file replacements for selected extensions
for ext in *.py *.toml *.yml *.md; do
  find . -type f -name "$ext" -print0 | while IFS= read -r -d '' f; do
    echo "Processing $f"
    sed $SED_IN -E "s/from\\s+${OLD_BASE}/from ${NEW_BASE}/g" "$f"
    sed $SED_IN -E "s/ZeroGate/ZeroGate/g" "$f"
    sed $SED_IN -E "s/ZEROGATE_/ZEROGATE_/g" "$f"
  done
done

# 4. Update metadata files
if [[ -f pyproject.toml ]]; then
  sed $SED_IN -E "s/name\s*=\s*\"${OLD_BASE}\"/name = \"${NEW_BASE}\"/g" pyproject.toml
  sed $SED_IN -E "s/description\s*=.*$/description = \"An autonomous, local‑first red‑team engine that maps code logic to detect and patch vulnerabilities using Graph‑RAG.\"/g" pyproject.toml
fi

if [[ -f docker-compose.yml ]]; then
  sed $SED_IN -E "s/graph-rag-db/zerogate-db/g" docker-compose.yml
  sed $SED_IN -E "s/graph-rag/zerogate/g" docker-compose.yml
fi

if [[ -f setup.py ]]; then
  sed $SED_IN -E "s/name\s*=\s*\"${OLD_BASE}\"/name = \"${NEW_BASE}\"/g" setup.py
  sed $SED_IN -E "s/description\s*=.*$/description = \"An autonomous, local‑first red‑team engine that maps code logic to detect and patch vulnerabilities using Graph‑RAG.\"/g" setup.py
fi

# 5. Create .env.zerogate template
cat > .env.zerogate <<'EOF'
# Zerogate environment template
ZEROGATE_DB_HOST=localhost
ZEROGATE_DB_PORT=5432
ZEROGATE_DB_USER=zerogate
ZEROGATE_DB_PASSWORD=secret
EOF

echo "=== Rebranding complete ==="
