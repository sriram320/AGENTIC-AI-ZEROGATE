"""Synthetic Sample Generator for ZeroGate Benchmark.

Generates 120 dynamic samples (30 per category) with varying code patterns,
variable names, and framework styles to ensure robust benchmarking.
"""

import json
import random
from pathlib import Path

# --- Configuration ---
SAMPLES_PER_CATEGORY = 30
OUTPUT_DIR = Path("tests/benchmark")
GROUND_TRUTH_FILE = OUTPUT_DIR / "ground_truth.json"

# --- Templates & Variations ---

VAR_NAMES = ["user_input", "payload", "raw_data", "query_param", "data", "incoming", "user_id", "search_term", "cmd", "val"]
SINK_NAMES = ["execute", "run", "query", "perform", "process", "handle"]
DB_NAMES = ["cursor", "conn", "db", "db_session", "connection", "client"]

def gen_sqli_pos():
    var = random.choice(VAR_NAMES)
    db = random.choice(DB_NAMES)
    sink = "execute"
    patterns = [
        f"{db}.{sink}('SELECT * FROM users WHERE id = ' + {var})",
        f"{db}.{sink}(f'UPDATE orders SET status = \"paid\" WHERE uid = {{{var}}}')",
        f"{db}.{sink}('DELETE FROM logs WHERE tag = \"%s\"' % {var})",
        f"{db}.{sink}('SELECT name FROM items WHERE cat = {{}}'.format({var}))",
        f"sql = 'SELECT * FROM secrets WHERE key = \"' + {var} + '\"'\n{db}.{sink}(sql)"
    ]
    return random.choice(patterns)

def gen_sqli_neg():
    var = random.choice(VAR_NAMES)
    db = random.choice(DB_NAMES)
    patterns = [
        f"{db}.execute('SELECT * FROM users WHERE id = ?', ({var},))",
        f"{db}.execute('UPDATE orders SET status = \"paid\" WHERE uid = :1', [{var}])",
        f"uid = int({var})\n{db}.execute(f'SELECT * FROM users WHERE id = {{uid}}')",
        f"User.objects.filter(name={var}).first()",
        f"item = session.query(Item).filter(Item.id == {var}).all()"
    ]
    return random.choice(patterns)

def gen_xss_pos():
    var = random.choice(VAR_NAMES)
    patterns = [
        f"return f'<html><body><h1>Hello {{{var}}}</h1></body></html>'",
        f"return render_template_string('<div>' + {var} + '</div>')",
        f"response.write('<span>' + {var} + '</span>')",
        f"document.getElementById('out').innerHTML = {var}  # JS Context",
        f"return \"<script>alert('\" + {var} + \"')</script>\""
    ]
    return random.choice(patterns)

def gen_xss_neg():
    var = random.choice(VAR_NAMES)
    patterns = [
        f"return render_template('index.html', name={var})  # Autoescape on",
        f"from html import escape\nreturn '<div>' + escape({var}) + '</div>'",
        f"import bleach\nreturn bleach.clean({var})",
        f"document.getElementById('out').innerText = {var}",
        f"return Markup.escape({var})"
    ]
    return random.choice(patterns)

def gen_rce_pos():
    var = random.choice(VAR_NAMES)
    patterns = [
        f"import os\nos.system('ping -c 1 ' + {var})",
        f"import subprocess\nsubprocess.run({var}, shell=True)",
        f"eval('check_status(' + {var} + ')')",
        f"import pickle\npickle.loads({var})",
        f"import os\nos.popen('ls ' + {var}).read()"
    ]
    return random.choice(patterns)

def gen_rce_neg():
    var = random.choice(VAR_NAMES)
    patterns = [
        f"import subprocess\nsubprocess.run(['ls', {var}], shell=False)",
        f"if {var}.isalnum():\n    os.system('echo ' + {var})",
        f"import json\njson.loads({var})",
        f"ALLOWED = ['status', 'version']\nif {var} in ALLOWED: os.system({var})",
        f"subprocess.check_call(['ping', '-c', '1', '127.0.0.1'])"
    ]
    return random.choice(patterns)

def gen_dep_pos():
    packages = [
        ("log4j", "2.14.1"), ("flask", "0.12"), ("requests", "2.6.0"), 
        ("django", "1.11"), ("struts2", "2.3.12"), ("spring-core", "5.2.0")
    ]
    pkg, ver = random.choice(packages)
    formats = [
        f"{pkg}=={ver}",
        f"\"{pkg}\": \"{ver}\"",
        f"<dependency>\n  <groupId>org.{pkg}</groupId>\n  <artifactId>{pkg}-core</artifactId>\n  <version>{ver}</version>\n</dependency>"
    ]
    return random.choice(formats)

def gen_dep_neg():
    packages = [
        ("flask", "3.0.0"), ("requests", "2.31.0"), ("django", "4.2"), 
        ("cryptography", "41.0.0"), ("pydantic", "2.5.0")
    ]
    pkg, ver = random.choice(packages)
    formats = [
        f"{pkg}=={ver}",
        f"\"{pkg}\": \"^{ver}\"",
        f"<version>{ver}</version>"
    ]
    return random.choice(formats)

# --- Generator Loop ---

def generate_all():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    samples_list = []
    
    categories = [
        ("SQL Injection", "sqli", gen_sqli_pos, gen_sqli_neg),
        ("XSS", "xss", gen_xss_pos, gen_xss_neg),
        ("RCE", "rce", gen_rce_pos, gen_rce_neg),
        ("Dependency", "dependency", gen_dep_pos, gen_dep_neg)
    ]
    
    for cat_name, cat_slug, pos_func, neg_func in categories:
        for i in range(1, SAMPLES_PER_CATEGORY + 1):
            is_positive = i <= (SAMPLES_PER_CATEGORY // 2)
            verdict = "VULNERABLE" if is_positive else "CLEAN"
            folder = "positive" if is_positive else "negative"
            ext = ".txt" if cat_slug == "dependency" else ".py"
            
            sample_id = f"{cat_slug}_{folder[:3]}_{i:02d}"
            rel_path = f"samples/{cat_slug}/{folder}/{sample_id}{ext}"
            abs_path = OUTPUT_DIR / rel_path
            
            # Generate content
            content = pos_func() if is_positive else neg_func()
            
            # Write file
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            abs_path.write_text(content, encoding="utf-8")
            
            # Add to ground truth
            samples_list.append({
                "id": sample_id,
                "file": rel_path,
                "category": cat_name,
                "expected_verdict": verdict,
                "expected_severity": "HIGH" if is_positive else "LOW",
                "description": f"Auto-generated {cat_name} {verdict.lower()} sample."
            })
            
    # Write ground_truth.json
    GROUND_TRUTH_FILE.write_text(json.dumps({"samples": samples_list}, indent=2), encoding="utf-8")
    print(f"Success: Generated 120 samples and updated {GROUND_TRUTH_FILE}")

if __name__ == "__main__":
    generate_all()
