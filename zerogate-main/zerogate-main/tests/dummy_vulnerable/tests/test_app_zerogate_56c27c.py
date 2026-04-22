import pytest
from your_module import get_user
import sqlite3

@pytest.fixture
def setup_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT)')
    cursor.execute("INSERT INTO users (id, name) VALUES ('1', 'John')")
    conn.commit()
    yield
    conn.close()

def test_get_user(setup_db):
    result = get_user('1')
    assert len(result) == 1
    assert result[0][0] == '1'
    assert result[0][1] == 'John'

def test_get_user_invalid_id(setup_db):
    result = get_user('2')
    assert len(result) == 0

def test_get_user_sql_injection(setup_db):
    result = get_user("1' OR 1=1 --")
    assert len(result) == 1
    assert result[0][0] == '1'
    assert result[0][1] == 'John'
