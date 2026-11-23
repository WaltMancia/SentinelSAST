import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from .models import GitRepoScanRequest, ScanReport, SnippetScanRequest
from .rules import RULES
from .scanner import build_report, scan_directory, scan_text_content

app = FastAPI(
    title="SentinelSAST API",
    description="Motor de análisis estático de seguridad (SAST) y auditoría de secretos para CI/CD.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SAFE_GIT_URL_REGEX = re.compile(r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$")


@app.get("/api/health")
def health_check():
    return {"status": "ok", "engine": "SentinelSAST v1.0", "rules_loaded": len(RULES) + 3}


@app.get("/api/rules")
def list_rules():
    return [
        {
            "rule_id": r.rule_id,
            "title": r.title,
            "category": r.category,
            "owasp": r.owasp,
            "cwe": r.cwe,
            "severity": r.severity,
            "cvss_score": r.cvss_score,
        }
        for r in RULES
    ]


@app.post("/api/scan/snippet", response_model=ScanReport)
def scan_snippet(payload: SnippetScanRequest):
    findings, lines_count = scan_text_content(payload.code, payload.filename)
    return build_report(
        target_name=payload.filename,
        scan_type="Code Snippet",
        files_scanned=1,
        lines_scanned=lines_count,
        findings=findings,
    )


@app.post("/api/scan/zip", response_model=ScanReport)
async def scan_zip_archive(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Solo se permiten archivos comprimidos en formato .zip")

    temp_dir = tempfile.mkdtemp(prefix="sentinelsast_zip_")
    zip_path = os.path.join(temp_dir, "upload.zip")
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        content = await file.read()
        if len(content) > 25 * 1024 * 1024:  # 25 MB limit
            raise HTTPException(status_code=413, detail="El archivo ZIP excede el límite de 25 MB.")

        with open(zip_path, "wb") as f:
            f.write(content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Protección contra Zip Slip
            for member in zf.namelist():
                member_path = os.path.realpath(os.path.join(extract_dir, member))
                if not member_path.startswith(os.path.realpath(extract_dir)):
                    raise HTTPException(status_code=400, detail="Archivo ZIP malicioso detectado (Zip Slip).")
            zf.extractall(extract_dir)

        return scan_directory(extract_dir, target_name=file.filename, scan_type="ZIP Archive")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="El archivo proporcionado no es un ZIP válido.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/scan/repo", response_model=ScanReport)
def scan_git_repository(payload: GitRepoScanRequest):
    url = payload.repo_url.strip()
    if not SAFE_GIT_URL_REGEX.match(url):
        raise HTTPException(
            status_code=400,
            detail="URL inválida. Usa una URL HTTPS pública de GitHub, GitLab o Bitbucket (ej. https://github.com/usuario/repo)."
        )

    temp_dir = tempfile.mkdtemp(prefix="sentinelsast_git_")
    clone_dir = os.path.join(temp_dir, "repo")

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, clone_dir],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail="No se pudo clonar el repositorio. Verifica que sea público y exista.")

        repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
        return scan_directory(clone_dir, target_name=repo_name, scan_type="Git Repository")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Tiempo de espera agotado al clonar el repositorio.")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
