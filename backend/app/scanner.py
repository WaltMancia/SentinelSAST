import ast
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple
from .models import Finding, ScanReport, ScanSummary, Severity
from .rules import RULES

IGNORED_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".idea", ".vscode", "coverage"
}

SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".php", ".java",
    ".cs", ".go", ".rb", ".sh", ".env", ".yml", ".yaml",
    ".json", ".xml", ".sql", ".html", ".tf"
}


def _scan_python_ast(content: str, file_path: str) -> List[Finding]:
    """Análisis AST específico para Python para detectar patrones semánticos."""
    findings: List[Finding] = []
    try:
        tree = ast.parse(content, filename=file_path)
    except SyntaxError:
        return findings

    lines = content.splitlines()

    for node in ast.walk(tree):
        # Detectar pickle.loads / yaml.load inseguro
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if func_name in {"pickle.loads", "pickle.load", "marshal.loads"}:
                line_no = getattr(node, "lineno", 1)
                snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else func_name
                findings.append(
                    Finding(
                        rule_id="AST-PY-001",
                        title="Insecure Deserialization (pickle/marshal)",
                        category="Insecure Deserialization",
                        owasp="A08:2021 - Software and Data Integrity Failures",
                        cwe="CWE-502",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet[:200],
                        description="La deserialización de datos no confiables con pickle/marshal permite ejecución arbitraria de código.",
                        remediation="Utiliza formatos de serialización seguros basados en datos como JSON."
                    )
                )

            if func_name == "yaml.load":
                has_safe_loader = any(
                    kw.arg == "Loader" and isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader"
                    for kw in node.keywords
                )
                if not has_safe_loader:
                    line_no = getattr(node, "lineno", 1)
                    snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else func_name
                    findings.append(
                        Finding(
                            rule_id="AST-PY-002",
                            title="Unsafe YAML Deserialization (yaml.load without SafeLoader)",
                            category="Insecure Deserialization",
                            owasp="A08:2021 - Software and Data Integrity Failures",
                            cwe="CWE-502",
                            severity=Severity.HIGH,
                            cvss_score=8.1,
                            file_path=file_path,
                            line_number=line_no,
                            code_snippet=snippet[:200],
                            description="yaml.load() sin SafeLoader puede instanciar objetos arbitrarios en Python.",
                            remediation="Usa yaml.safe_load() o pasa Loader=yaml.SafeLoader explícitamente."
                        )
                    )

        # Detectar assert en código de producción (eliminado con python -O)
        if isinstance(node, ast.Assert):
            line_no = getattr(node, "lineno", 1)
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else "assert ..."
            if any(k in snippet.lower() for k in ("auth", "admin", "perm", "role", "token", "is_")):
                findings.append(
                    Finding(
                        rule_id="AST-PY-003",
                        title="Security Control Enforced via assert Statement",
                        category="Security Misconfiguration",
                        owasp="A01:2021 - Broken Access Control",
                        cwe="CWE-617",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        file_path=file_path,
                        line_number=line_no,
                        code_snippet=snippet[:200],
                        description="Las sentencias assert se omiten cuando Python se ejecuta con el flag de optimización (-O).",
                        remediation="Reemplaza assert por condicionales explícitos (if not ...: raise PermissionError())."
                    )
                )

    return findings


def scan_text_content(content: str, file_path: str) -> Tuple[List[Finding], int]:
    findings: List[Finding] = []
    lines = content.splitlines()
    lower_path = file_path.lower()

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "/*", "*")):
            continue

        for rule in RULES:
            if rule.file_extensions:
                if not any(lower_path.endswith(ext) for ext in rule.file_extensions):
                    continue

            if rule.pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        category=rule.category,
                        owasp=rule.owasp,
                        cwe=rule.cwe,
                        severity=rule.severity,
                        cvss_score=rule.cvss_score,
                        file_path=file_path,
                        line_number=idx,
                        code_snippet=stripped[:200],
                        description=rule.description,
                        remediation=rule.remediation,
                    )
                )

    if lower_path.endswith(".py"):
        findings.extend(_scan_python_ast(content, file_path))

    return findings, len(lines)


def build_report(target_name: str, scan_type: str, files_scanned: int, lines_scanned: int, findings: List[Finding]) -> ScanReport:
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
    }
    findings.sort(key=lambda f: (severity_order[f.severity], f.file_path, f.line_number))

    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)

    raw_penalty = crit * 25 + high * 12 + med * 5 + low * 1
    risk_score = min(100, raw_penalty)

    summary = ScanSummary(
        total_files_scanned=files_scanned,
        total_lines_scanned=lines_scanned,
        total_findings=len(findings),
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        risk_score=risk_score,
    )

    return ScanReport(
        scan_id=str(uuid.uuid4())[:8].upper(),
        target_name=target_name,
        scan_type=scan_type,
        timestamp=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        findings=findings,
    )


def scan_directory(root_dir: str, target_name: str, scan_type: str) -> ScanReport:
    all_findings: List[Finding] = []
    files_scanned = 0
    lines_scanned = 0

    for current_root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for fname in files:
            ext = Path(fname).suffix.lower()
            if ext not in SCANNABLE_EXTENSIONS and not fname.startswith(".env"):
                continue

            full_path = os.path.join(current_root, fname)
            rel_path = os.path.relpath(full_path, root_dir).replace("\\", "/")

            try:
                if os.path.getsize(full_path) > 1_000_000:  # 1 MB max per file
                    continue
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                f_findings, f_lines = scan_text_content(content, rel_path)
                all_findings.extend(f_findings)
                files_scanned += 1
                lines_scanned += f_lines
            except OSError:
                continue

    return build_report(target_name, scan_type, files_scanned, lines_scanned, all_findings)
