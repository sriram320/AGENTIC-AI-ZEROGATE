import mgclient
from loguru import logger

conn = mgclient.connect(host="127.0.0.1", port=7687)
cursor = conn.cursor()


def test(name, q):
    try:
        cursor.execute(q)
        row = cursor.fetchone()
        logger.info(f"Test '{name}' result: {row}")
    except Exception as e:
        logger.error(f"Test '{name}' failed: {e}")


q1 = r"""MATCH (f) WHERE toLower(f.source_code) =~ "[\\s\\S]*(password|secret|api_key|access_key|api_secret|token|private_key)\\s*=\\s*['\"][a-z0-9_\\-!@#$%^]{8,}['\"][\\s\\S]*" RETURN f"""
test("Hardcoded Secrets with toLower", q1)

q2 = r"""MATCH (f) WHERE f.source_code =~ "[\\s\\S]*(execute|raw_sql|cursor)[\\s\\S]*f['\"].*\\{.*\\}[\\s\\S]*" RETURN f"""
test("SQLi with fixed tail", q2)
