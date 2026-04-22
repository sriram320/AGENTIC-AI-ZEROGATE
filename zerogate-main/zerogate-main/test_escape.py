import mgclient
from loguru import logger


def test(name, q):
    try:
        conn = mgclient.connect(host="127.0.0.1", port=7687)
        cursor = conn.cursor()
        cursor.execute(q)
        count = cursor.fetchone()[0]
        logger.info(f"Test '{name}': {count} nodes found.")
    except Exception as e:
        logger.error(f"Test '{name}' failed: {e}")


test(
    "Double Backslash Dot",
    r"""MATCH (f:Function) WHERE f.source_code =~ ".*foo\\..*" RETURN count(f)""",
)

test(
    "Double Backslash Brace",
    r"""MATCH (f:Function) WHERE f.source_code =~ ".*foo\\{.*" RETURN count(f)""",
)

test(
    "Double Escapes",
    r"""MATCH (f:Function) WHERE f.source_code =~ ".*(execute|raw_sql|cursor).*f['\"].*\\{.*}.*" RETURN count(f) LIMIT 1""",
)

test(
    "Double Escapes CMD",
    r"""MATCH (f:Function) WHERE f.source_code =~ ".*(os\\.system|subprocess\\.call|subprocess\\.Popen|exec\\(|eval\\().*" RETURN count(f) LIMIT 1""",
)
