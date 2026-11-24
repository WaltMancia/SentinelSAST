import React, { useState } from 'react';
import {
  ShieldAlert,
  Code2,
  GitBranch,
  FileArchive,
  Play,
  Download,
  AlertTriangle,
  CheckCircle2,
  FileCode,
  Terminal,
  Sparkles
} from 'lucide-react';
import { ScanReport, Severity } from './types';

const DEMO_VULNERABLE_CODE = `import os
import sqlite3
import pickle
import requests

# Configuración heredada (¡No subir a producción!)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
APP_SECRET_KEY = "demo_secret_token_not_real_987654"

def authenticate_user(username, password_input):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Vulnerable a SQL Injection
    query = "SELECT id, role FROM users WHERE username = '" + username + "' AND password = '" + password_input + "'"
    cursor.execute(query)
    return cursor.fetchone()

def load_user_preferences(serialized_blob):
    # Deserialización insegura detectada vía AST
    return pickle.loads(serialized_blob)

def fetch_external_webhook(url):
    # Validación TLS desactivada (MitM)
    return requests.get(url, verify=False)
`;

const SEVERITY_BADGES: Record<Severity, string> = {
  CRITICAL: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
  HIGH: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  LOW: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
};

export default function App() {
  const [activeTab, setActiveTab] = useState<'snippet' | 'repo' | 'zip'>('snippet');
  const [filename, setFilename] = useState('auth_service.py');
  const [code, setCode] = useState(DEMO_VULNERABLE_CODE);
  const [repoUrl, setRepoUrl] = useState('');
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      let response: Response;

      if (activeTab === 'snippet') {
        response = await fetch('/api/scan/snippet', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename, code }),
        });
      } else if (activeTab === 'repo') {
        response = await fetch('/api/scan/repo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repo_url: repoUrl }),
        });
      } else {
        if (!zipFile) {
          throw new Error('Selecciona un archivo .zip primero.');
        }
        const formData = new FormData();
        formData.append('file', zipFile);
        response = await fetch('/api/scan/zip', {
          method: 'POST',
          body: formData,
        });
      }

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || 'Error al ejecutar el análisis SAST.');
      }

      setReport(data);
      setSeverityFilter('ALL');
    } catch (err: any) {
      setError(err.message || 'No se pudo conectar con el motor de análisis.');
    } finally {
      setLoading(false);
    }
  };

  const exportJsonReport = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinelsast-report-${report.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredFindings = report
    ? report.findings.filter((f) => severityFilter === 'ALL' || f.severity === severityFilter)
    : [];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Navbar */}
      <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
              <ShieldAlert className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="font-bold text-lg tracking-tight text-white">
                Sentinel<span className="text-emerald-400">SAST</span>
              </h1>
              <p className="text-xs text-slate-400">Static Application Security Testing & Secret Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-800/80 px-3 py-1.5 rounded-full border border-slate-700">
            <Terminal className="w-3.5 h-3.5 text-emerald-400" />
            <span>AST + Regex Engine v1.0</span>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Scanner Input Panel */}
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="border-b border-slate-800 flex flex-wrap items-center justify-between px-4 pt-3 gap-2 bg-slate-900/90">
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setActiveTab('snippet')}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
                  activeTab === 'snippet'
                    ? 'border-emerald-400 text-emerald-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Code2 className="w-4 h-4" />
                Fragmento de Código
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('repo')}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
                  activeTab === 'repo'
                    ? 'border-emerald-400 text-emerald-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <GitBranch className="w-4 h-4" />
                Repositorio Git
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('zip')}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
                  activeTab === 'zip'
                    ? 'border-emerald-400 text-emerald-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileArchive className="w-4 h-4" />
                Archivo .ZIP
              </button>
            </div>

            {activeTab === 'snippet' && (
              <button
                type="button"
                onClick={() => {
                  setFilename('auth_service.py');
                  setCode(DEMO_VULNERABLE_CODE);
                }}
                className="text-xs flex items-center gap-1.5 text-emerald-400 hover:text-emerald-300 pb-2"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Cargar Demo Vulnerable
              </button>
            )}
          </div>

          <form onSubmit={handleScan} className="p-6 space-y-4">
            {activeTab === 'snippet' && (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Nombre del archivo (define el parser AST / extensión)
                  </label>
                  <input
                    type="text"
                    value={filename}
                    onChange={(e) => setFilename(e.target.value)}
                    placeholder="ej. app.py, server.js, package.json"
                    className="w-full sm:w-80 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">
                    Código fuente a auditar
                  </label>
                  <textarea
                    rows={10}
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 font-mono text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
                    placeholder="Pega aquí tu código..."
                    required
                  />
                </div>
              </div>
            )}

            {activeTab === 'repo' && (
              <div className="space-y-2">
                <label className="block text-xs font-medium text-slate-400">
                  URL pública del repositorio (GitHub, GitLab o Bitbucket)
                </label>
                <input
                  type="url"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/usuario/proyecto-vulnerable"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
                  required
                />
                <p className="text-xs text-slate-500">
                  Se realiza un clonado superficial (--depth 1) en un entorno temporal aislado que se destruye al finalizar.
                </p>
              </div>
            )}

            {activeTab === 'zip' && (
              <div className="space-y-2">
                <label className="block text-xs font-medium text-slate-400">
                  Sube un paquete comprimido (.zip, máximo 25 MB)
                </label>
                <input
                  type="file"
                  accept=".zip"
                  onChange={(e) => setZipFile(e.target.files?.[0] || null)}
                  className="block w-full text-sm text-slate-300 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-emerald-500/15 file:text-emerald-400 hover:file:bg-emerald-500/25 cursor-pointer"
                  required
                />
              </div>
            )}

            {error && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div className="flex justify-end">
              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-slate-950 font-semibold px-5 py-2.5 rounded-lg text-sm transition shadow-lg shadow-emerald-500/10"
              >
                <Play className="w-4 h-4 fill-current" />
                {loading ? 'Analizando código...' : 'Ejecutar Auditoría SAST'}
              </button>
            </div>
          </form>
        </section>

        {/* Results Dashboard */}
        {report && (
          <section className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <p className="text-xs text-slate-400">Risk Score</p>
                <p className="text-2xl font-bold text-white mt-1">
                  {report.summary.risk_score}
                  <span className="text-xs font-normal text-slate-500"> / 100</span>
                </p>
                <p className="text-xs text-slate-500 mt-1">{report.summary.total_files_scanned} archivo(s)</p>
              </div>
              <div className="bg-slate-900 border border-rose-500/20 rounded-xl p-4">
                <p className="text-xs text-rose-400">Critical</p>
                <p className="text-2xl font-bold text-rose-400 mt-1">{report.summary.critical_count}</p>
              </div>
              <div className="bg-slate-900 border border-orange-500/20 rounded-xl p-4">
                <p className="text-xs text-orange-400">High</p>
                <p className="text-2xl font-bold text-orange-400 mt-1">{report.summary.high_count}</p>
              </div>
              <div className="bg-slate-900 border border-amber-500/20 rounded-xl p-4">
                <p className="text-xs text-amber-400">Medium</p>
                <p className="text-2xl font-bold text-amber-400 mt-1">{report.summary.medium_count}</p>
              </div>
              <div className="bg-slate-900 border border-sky-500/20 rounded-xl p-4">
                <p className="text-xs text-sky-400">Low</p>
                <p className="text-2xl font-bold text-sky-400 mt-1">{report.summary.low_count}</p>
              </div>
            </div>

            {/* Filter & Export Bar */}
            <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs text-slate-400 mr-1">Filtrar severidad:</span>
                {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-3 py-1 rounded-md text-xs font-medium transition ${
                      severityFilter === sev
                        ? 'bg-emerald-500 text-slate-950'
                        : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              <button
                onClick={exportJsonReport}
                className="inline-flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-3.5 py-1.5 rounded-lg text-xs font-medium transition"
              >
                <Download className="w-3.5 h-3.5" />
                Exportar Reporte JSON (CI/CD)
              </button>
            </div>

            {/* Findings List */}
            {filteredFindings.length === 0 ? (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-2">
                <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
                <h3 className="text-base font-semibold text-white">Sin hallazgos en esta categoría</h3>
                <p className="text-sm text-slate-400">
                  No se detectaron vulnerabilidades ni secretos expuestos para el filtro seleccionado.
                </p>
              </div>
            ) : (
              <div className="space-y-4">
                {filteredFindings.map((finding, index) => (
                  <div
                    key={`${finding.rule_id}-${finding.line_number}-${index}`}
                    className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span
                            className={`px-2.5 py-0.5 rounded text-xs font-semibold border ${
                              SEVERITY_BADGES[finding.severity]
                            }`}
                          >
                            {finding.severity} (CVSS {finding.cvss_score})
                          </span>
                          <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                            {finding.rule_id} • {finding.cwe}
                          </span>
                          <span className="text-xs text-slate-500">{finding.owasp}</span>
                        </div>
                        <h3 className="text-base font-semibold text-white">{finding.title}</h3>
                      </div>

                      <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20">
                        <FileCode className="w-3.5 h-3.5" />
                        <span>
                          {finding.file_path}:{finding.line_number}
                        </span>
                      </div>
                    </div>

                    <p className="text-sm text-slate-300">{finding.description}</p>

                    <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-rose-300 overflow-x-auto">
                      <code>{finding.code_snippet}</code>
                    </div>

                    <div className="bg-emerald-950/30 border border-emerald-500/20 rounded-lg p-3 text-xs text-emerald-200">
                      <strong className="font-semibold text-emerald-400">Remediación: </strong>
                      {finding.remediation}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
