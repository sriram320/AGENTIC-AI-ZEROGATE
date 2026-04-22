import sqlite3

def get_user(user_id: str):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # SQL Injection Vulnerability
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cursor.fetchall()

def exec_cmd(cmd: str):
    import os
    # OS Command Injection
    os.system("ping " + cmd)
