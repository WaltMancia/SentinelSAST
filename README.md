# 🛡️ SentinelSAST — Code & Secrets Auditor for CI/CD

**SentinelSAST** es una plataforma de análisis estático de seguridad de aplicaciones (**SAST**) y detección de credenciales expuestas diseñada para entornos **AppSec** y **DevSecOps**.

Permite auditar fragmentos de código, archivos `.zip` y repositorios públicos de Git en busca de vulnerabilidades del **OWASP Top 10**, deserialización insegura mediante análisis de árboles sintácticos (**AST**) y secretos hardcodeados, generando reportes estructurados con puntuación **CVSS** y guías de remediación.

---

## ✨ Características Principales

* **Motor Híbrido (AST + Regex):** Combina expresiones regulares de alta precisión para secretos (AWS Keys, GitHub Tokens, llaves privadas PEM, API keys) con inspección de **Abstract Syntax Trees (AST)** en Python para detectar vulnerabilidades semánticas (`pickle.loads`, `yaml.load` inseguro, controles de acceso con `assert`).
* **Múltiples Modos de Entrada:**
  * **Snippet en vivo:** Editor interactivo con código vulnerable de demostración incluido.
  * **Archivo `.zip`:** Extracción segura con protección contra ataques *Zip Slip*.
  * **Repositorio Git:** Clonado superficial (`--depth 1`) en sandbox temporal aislado.
* **Clasificación Estándar de Seguridad:** Mapeo directo a **OWASP Top 10**, **CWE** y severidad **CVSS v3**.
* **Exportación para CI/CD:** Descarga de reportes en formato JSON listos para integrarse en pipelines automatizados.

---

## 🏗️ Arquitectura y Stack Tecnológico

* **Backend:** Python 3.12, FastAPI, módulo nativo `ast`, Pydantic.
* **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, Lucide Icons.
* **Infraestructura & CI:** Docker, Docker Compose, Nginx (reverse proxy) y GitHub Actions.

---

## 🚀 Despliegue Rápido con Docker

```bash
docker compose up --build -d
```

* **Interfaz Web (UI):** `http://localhost:5173`
* **API & Documentación Swagger:** `http://localhost:8000/docs`

---

## 💻 Ejecución Local (Desarrollo)

### 1. Backend (FastAPI)
```bash
cd backend
python -m venv .venv
# En Windows PowerShell:
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend (React + Vite)
```bash
cd frontend
npm install
npm run dev
```

---

## 🧪 Ejecutar Pruebas Unitarias

```bash
cd backend
pytest
```
