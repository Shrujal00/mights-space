/* Shapes returned by the backend. Mirrors app/api/samples.py exactly — every
 * field here is one the API actually sends, and nothing is inferred. */

export type Verdict = "malicious" | "suspicious" | "unknown";
export type SampleStatus = "queued" | "detonating" | "complete" | "failed";
export type ProviderState = "ok" | "not_found" | "unavailable" | "skipped";

export interface Health {
  status: string;
  offline_mode: boolean;
  yara_rules_loaded: number;
  yara_rules_skipped: number;
}

export interface UploadReceipt {
  id: number;
  sha256: string;
  status: SampleStatus;
  duplicate: boolean;
}

export interface SampleSummary {
  id: number;
  sha256: string;
  filename: string;
  size: number;
  /* What the analysis found the file to be. Empty until it has been read. */
  detected_type: string;
  status: SampleStatus;
  verdict: Verdict | null;
  headline: string | null;
  created_at: string | null;
}

export interface PeSection {
  name: string;
  entropy: number;
  raw_size: number;
  virtual_size: number;
}

export interface ApkSignal {
  code: string;
  plain_language: string;
  detail: string;
}

export interface ApkCertificate {
  subject: string;
  issuer: string;
  sha256: string;
  self_signed: boolean;
}

export interface NotableString {
  value: string;
  category: string;
  why: string;
}

export interface LeafFile {
  relative_name: string;
  sha256: string;
  detected_type: string;
  size: number;
  is_pe: boolean;
  machine: string | null;
  likely_packed: boolean;
  packing_reasons: string[];
  imported_dlls: string[];
  sections: PeSection[];

  is_apk: boolean;
  package: string | null;
  app_label: string | null;
  permissions: string[];
  dangerous_permissions: string[];
  high_abuse_permissions: string[];
  components: {
    activities?: string[];
    services?: string[];
    receivers?: string[];
    providers?: string[];
  };
  certificates: ApkCertificate[];
  signals: ApkSignal[];
  notable_strings: NotableString[];
}

export interface ThreatFoxData {
  malware?: string | null;
  threat_type?: string | null;
  confidence?: number | null;
  ioc?: string | null;
  first_seen?: string | null;
}

export interface AbuseIpdbData {
  abuse_confidence?: number | null;
  total_reports?: number | null;
  country?: string | null;
  isp?: string | null;
  domain?: string | null;
  last_reported?: string | null;
}

export interface UrlscanData {
  result_count?: number | null;
  latest_url?: string | null;
  latest_scan_time?: string | null;
}

export interface Indicator {
  type: "url" | "ipv4" | "domain";
  value: string;
  threatfox: ThreatFoxData | null;
  abuseipdb: AbuseIpdbData | null;
  urlscan: UrlscanData | null;
}

export interface YaraHit {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Record<string, string>;
}

export interface Technique {
  technique_id: string;
  name: string;
  plain_language: string;
  evidence: string[];
  basis: string;
}

export type EventCategory =
  | "process" | "file" | "network" | "data-access" | "registry" | "crypto";

export interface BehaviorEvent {
  at: string | null;
  offset_ms: number;
  category: EventCategory;
  action: string;
  target: string;
  detail: string;
  source: string;
  size_bytes: number | null;
  record_count: number | null;
  basis: "dynamic-observed";
}

export interface ExfiltrationFinding {
  what: string;
  where: string;
  when: string | null;
  gap_ms: number | null;
  bytes_sent: number | null;
  confidence: "strong" | "probable";
}

/* One line the sandbox reported while it was working. Real messages, not a
 * decorative progress bar — a detonation takes minutes and the wait must not
 * be silent for whoever is watching. */
export interface ProgressEntry {
  at: string | null;
  message: string;
}

export interface DetonationRun {
  platform: "android" | "windows";
  engine: "frida" | "speakeasy";
  status: "queued" | "running" | "complete" | "failed" | "timeout";
  started_at: string | null;
  finished_at: string | null;
  error: string;
  timed: boolean;
  coverage: string;
  artifacts: Record<string, string>;
  progress: ProgressEntry[];
  events: BehaviorEvent[];
  exfiltration: ExfiltrationFinding[];
}

export interface ProviderStatus {
  provider: string;
  status: ProviderState;
  detail: string;
}

export interface Report {
  id: number;
  sha256: string;
  md5: string;
  sha1: string;
  filename: string;
  size: number;
  detected_type: string;
  status: SampleStatus;
  verdict: Verdict | null;
  headline: string | null;
  narrative: string | null;
  reasons: string[];
  warnings: string[];
  error: string | null;
  created_at: string | null;
  completed_at: string | null;
  files: LeafFile[];
  indicators: Indicator[];
  yara: YaraHit[];
  techniques: Technique[];
  providers: ProviderStatus[];
  detonations: DetonationRun[];
  /* Whether this server could run this file if asked. Drives the behavioural
   * analysis button — false when no sandbox is configured, the sample is still
   * being read, or a run is already in flight. */
  can_detonate: boolean;
}
