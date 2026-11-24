export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Finding {
  rule_id: string;
  title: string;
  category: string;
  owasp: string;
  cwe: string;
  severity: Severity;
  cvss_score: number;
  file_path: string;
  line_number: number;
  code_snippet: string;
  description: string;
  remediation: string;
}

export interface ScanSummary {
  total_files_scanned: number;
  total_lines_scanned: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  risk_score: number;
}

export interface ScanReport {
  scan_id: string;
  target_name: string;
  scan_type: string;
  timestamp: string;
  summary: ScanSummary;
  findings: Finding[];
}
