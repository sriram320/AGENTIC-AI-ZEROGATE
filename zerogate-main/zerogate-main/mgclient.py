"""A shim for mgclient that uses the neo4j driver. 
Required for Windows environments where building pymgclient is problematic.
"""
from __future__ import annotations
import neo4j
from typing import Any

def connect(host="localhost", port=7687, username=None, password=None, **kwargs):
    return Connection(host, port, username, password)

class Connection:
    def __init__(self, host, port, username, password):
        uri = f"bolt://{host}:{port}"
        auth = (username, password) if username else None
        self.driver = neo4j.GraphDatabase.driver(uri, auth=auth)
        self.autocommit = True

    def cursor(self):
        return Cursor(self)

    def close(self):
        self.driver.close()

    def commit(self):
        pass

    def rollback(self):
        pass

class Cursor:
    def __init__(self, connection):
        self.connection = connection
        self.session = connection.driver.session()
        self.result = None
        self.description = None

    def execute(self, query, params=None):
        # mgclient uses %(name)s while neo4j uses $name
        # Simple heuristic conversion
        import re
        if params:
            for key in params.keys():
                query = query.replace(f"%({key})s", f"${key}")
        
        self.result = self.session.run(query, params or {})
        
        # Mock description
        keys = self.result.keys()
        self.description = [type('Column', (), {'name': k})() for k in keys]

    def fetchall(self):
        if not self.result:
            return []
        return [tuple(record.values()) for record in self.result]

    def fetchone(self):
        if not self.result:
            return None
        record = self.result.single()
        return tuple(record.values()) if record else None

    def close(self):
        if self.session:
            self.session.close()
