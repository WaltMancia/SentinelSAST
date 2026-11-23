from app.scanner import scan_text_content


def test_detects_aws_key_and_sqli():
    vulnerable_code = '''
import sqlite3
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user(user_input):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    return conn.execute(query).fetchall()
'''
    findings, lines = scan_text_content(vulnerable_code, "vuln_service.py")
    rule_ids = {f.rule_id for f in findings}
    assert "SEC-001" in rule_ids
    assert "SAST-001" in rule_ids
    assert lines > 5


def test_detects_python_ast_pickle():
    code = '''
import pickle
def load_session(raw):
    return pickle.loads(raw)
'''
    findings, _ = scan_text_content(code, "session.py")
    assert any(f.rule_id == "AST-PY-001" for f in findings)
