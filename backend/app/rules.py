import re
from dataclasses import dataclass
from typing import Pattern
from .models import Severity


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    title: str
    category: str
    owasp: str
    cwe: str
    severity: Severity
    cvss_score: float
    pattern: Pattern
    file_extensions: tuple
    description: str
    remediation: str


RULES: list[SecurityRule] = [
    SecurityRule(
        rule_id="SEC-001",
        title="AWS Access Key ID Hardcoded",
        category="Secrets & Credentials",
        owasp="A07:2021 - Identification and Authentication Failures",
        cwe="CWE-798",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        pattern=re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
        file_extensions=(),
        description="Se detectó una clave de acceso de AWS expuesta directamente en el código fuente.",
        remediation="Revoca la credencial inmediatamente en AWS IAM y utiliza variables de entorno o AWS Secrets Manager."
    ),
    SecurityRule(
        rule_id="SEC-002",
        title="Private Key (PEM) Exposed",
        category="Secrets & Credentials",
        owasp="A02:2021 - Cryptographic Failures",
        cwe="CWE-321",
        severity=Severity.CRITICAL,
        cvss_score=9.5,
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        file_extensions=(),
        description="Se encontró el encabezado de una llave privada criptográfica embebida en el repositorio.",
        remediation="Elimina la llave privada del historial de Git, rota el certificado/par de claves e inclúyela en .gitignore."
    ),
    SecurityRule(
        rule_id="SEC-003",
        title="Generic API Token / Secret Hardcoded",
        category="Secrets & Credentials",
        owasp="A07:2021 - Identification and Authentication Failures",
        cwe="CWE-798",
        severity=Severity.HIGH,
        cvss_score=8.2,
        pattern=re.compile(r"(?i)(?:api_key|apikey|secret_key|auth_token|password|passwd|jwt_secret)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{12,}['"]"),
        file_extensions=(),
        description="Posible secreto, contraseña o token de API definido como texto plano en una variable.",
        remediation="Extrae el secreto a un archivo .env no versionado o a un gestor de secretos (Vault, KMS)."
    ),
    SecurityRule(
        rule_id="SEC-004",
        title="GitHub Personal Access Token",
        category="Secrets & Credentials",
        owasp="A07:2021 - Identification and Authentication Failures",
        cwe="CWE-798",
        severity=Severity.CRITICAL,
        cvss_score=9.4,
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
        file_extensions=(),
        description="Se detectó un token personal o de aplicación de GitHub en el código.",
        remediation="Revoca el token desde GitHub Developer Settings y usa GitHub Actions Secrets."
    ),
    SecurityRule(
        rule_id="SAST-001",
        title="Potential SQL Injection via String Concatenation",
        category="Injection",
        owasp="A03:2021 - Injection",
        cwe="CWE-89",
        severity=Severity.CRITICAL,
        cvss_score=9.1,
        pattern=re.compile(r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?(?:\+|%s|\$\{|\{).*?(?:FROM|INTO|SET|WHERE)"),
        file_extensions=(".py", ".js", ".ts", ".php", ".java", ".cs", ".go"),
        description="Construcción dinámica de consultas SQL concatenando entradas o variables sin parametrización.",
        remediation="Utiliza consultas parametrizadas (Prepared Statements) o un ORM seguro."
    ),
    SecurityRule(
        rule_id="SAST-002",
        title="Dangerous Use of eval() or exec()",
        category="Code Injection",
        owasp="A03:2021 - Injection",
        cwe="CWE-95",
        severity=Severity.HIGH,
        cvss_score=8.6,
        pattern=re.compile(r"(?:eval|exec)\s*\("),
        file_extensions=(".py", ".js", ".ts", ".php"),
        description="La ejecución dinámica de cadenas puede permitir Ejecución Remota de Código (RCE) si la entrada es controlable.",
        remediation="Reemplaza eval()/exec() por parsers seguros como json.loads(), ast.literal_eval() o lógica explícita."
    ),
    SecurityRule(
        rule_id="SAST-003",
        title="OS Command Injection Risk (shell=True / child_process.exec)",
        category="Command Injection",
        owasp="A03:2021 - Injection",
        cwe="CWE-78",
        severity=Severity.HIGH,
        cvss_score=8.8,
        pattern=re.compile(r"(?:subprocess\.(?:Popen|run|call)\(.*shell\s*=\s*True|child_process\.exec\s*\(|os\.system\s*\()"),
        file_extensions=(".py", ".js", ".ts"),
        description="Invocación de comandos del sistema operativo mediante shell intérprete.",
        remediation="Pasa argumentos como lista de strings con shell=False o utiliza execFile() validando la entrada."
    ),
    SecurityRule(
        rule_id="SAST-004",
        title="DOM XSS Sink (dangerouslySetInnerHTML / innerHTML)",
        category="Cross-Site Scripting (XSS)",
        owasp="A03:2021 - Injection",
        cwe="CWE-79",
        severity=Severity.MEDIUM,
        cvss_score=6.5,
        pattern=re.compile(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\()"),
        file_extensions=(".js", ".jsx", ".ts", ".tsx", ".html"),
        description="Inyección directa de HTML en el DOM sin sanitización previa.",
        remediation="Sanitiza el contenido HTML usando DOMPurify antes de renderizarlo o usa textContent."
    ),
    SecurityRule(
        rule_id="SAST-005",
        title="Weak Cryptographic Hash (MD5 / SHA-1)",
        category="Cryptography",
        owasp="A02:2021 - Cryptographic Failures",
        cwe="CWE-328",
        severity=Severity.MEDIUM,
        cvss_score=5.9,
        pattern=re.compile(r"(?i)(?:hashlib\.(?:md5|sha1)|crypto\.createHash\(['"](?:md5|sha1)['"]\)|MD5\.Create|SHA1\.Create)"),
        file_extensions=(".py", ".js", ".ts", ".cs", ".java", ".go"),
        description="Uso de algoritmos de hash obsoletos y vulnerables a colisiones (MD5 o SHA-1).",
        remediation="Migra a SHA-256/SHA-3 para integridad o Argon2id/BCrypt para almacenamiento de contraseñas."
    ),
    SecurityRule(
        rule_id="SAST-006",
        title="TLS/SSL Certificate Verification Disabled",
        category="Misconfiguration",
        owasp="A05:2021 - Security Misconfiguration",
        cwe="CWE-295",
        severity=Severity.HIGH,
        cvss_score=7.4,
        pattern=re.compile(r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)"),
        file_extensions=(".py", ".js", ".ts", ".go"),
        description="La validación de certificados TLS está deshabilitada, exponiendo la comunicación a ataques Man-in-the-Middle (MitM).",
        remediation="Habilita la verificación estricta de certificados TLS en entornos de producción."
    ),
    SecurityRule(
        rule_id="DEP-001",
        title="Unpinned or Wildcard Dependency Version",
        category="Software Supply Chain",
        owasp="A06:2021 - Vulnerable and Outdated Components",
        cwe="CWE-1104",
        severity=Severity.LOW,
        cvss_score=3.7,
        pattern=re.compile(r"['"][^'"]+['"]\s*:\s*['"](?:\*|latest)['"]"),
        file_extensions=("package.json",),
        description="Dependencia declarada con comodín '*' o 'latest', lo que rompe builds deterministas y facilita supply-chain attacks.",
        remediation="Fija versiones exactas o rangos controlados y utiliza lockfiles (package-lock.json)."
    ),
]
