import os
import sqlite3
import subprocess

def run_command(user_input):
    # Command Injection Vulnerability
    os.system(f"echo {user_input}")
    subprocess.run(user_input, shell=True)

def get_user_data(user_id):
    # SQL Injection Vulnerability
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchall()

def read_file(filename):
    # Path Traversal Vulnerability
    with open("/var/www/data/" + filename, "r") as f:
        return f.read()

def render_template(user_input):
    # XSS Vulnerability (Simulated)
    template = f"<html><body>Hello, {user_input}</body></html>"
    return template

if __name__ == "__main__":
    # Hardcoded secrets
    SECRET_API_KEY = "sk-1234567890abcdef1234567890abcdef"
    DB_PASSWORD = "super_secret_password"
