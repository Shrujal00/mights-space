/* Presentation helpers. Everything here exists to make machine output readable
 * to someone who does not work with malware for a living. */

export function fileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

const RELATIVE = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const STEPS: [limit: number, unit: Intl.RelativeTimeFormatUnit, per: number][] = [
  [60, "second", 1],
  [3600, "minute", 60],
  [86400, "hour", 3600],
  [604800, "day", 86400],
];

export function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";

  const elapsed = (Date.now() - then) / 1000;
  if (elapsed < 45) return "just now";

  for (const [limit, unit, per] of STEPS) {
    if (elapsed < limit) return RELATIVE.format(-Math.round(elapsed / per), unit);
  }
  return absoluteDate(iso);
}

export function absoluteDate(iso: string | null): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/* The pipeline's own file-type strings are long and comma-heavy
 * ("PE32 executable (GUI) Intel 80386, for MS Windows, 5 sections"). The first
 * clause is the part that identifies the file; the rest is detail. */
export function shortType(detected: string): string {
  if (!detected) return "Unrecognised format";
  return detected.split(",")[0].trim();
}

/* A technique's plain-language text is written as "Can record everything typed
 * on the keyboard…". Under a heading that already says what it can do, the
 * leading "Can " is repetition. */
export function withoutCan(text: string): string {
  const stripped = text.replace(/^can\s+/i, "");
  return stripped.charAt(0).toUpperCase() + stripped.slice(1);
}

export const INDICATOR_LABELS: Record<string, string> = {
  ipv4: "Address",
  domain: "Domain",
  url: "Web address",
};

/* Provider keys are internal names. These are what an investigator would call
 * the sources, so the report can say who was asked without a glossary. */
export const PROVIDER_LABELS: Record<string, string> = {
  virustotal: "VirusTotal",
  malwarebazaar: "MalwareBazaar",
  threatfox: "ThreatFox",
  abuseipdb: "AbuseIPDB",
  urlscan: "urlscan.io",
};

export const PROVIDER_STATE_LABELS: Record<string, string> = {
  ok: "Answered",
  not_found: "No record",
  unavailable: "Unreachable",
  skipped: "Not asked",
};

/** Format millisecond offset as +Xs or +X.Xs */
export function formatOffset(ms: number): string {
  const seconds = ms / 1000;
  if (seconds < 10) return `+${seconds.toFixed(2)}s`;
  if (seconds < 60) return `+${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `+${mins}m${secs.toFixed(0)}s`;
}

/** Format byte count, returning null display for null input */
export function formatBytes(bytes: number | null): string | null {
  if (bytes === null) return null;
  return fileSize(bytes);
}

/** Format record count, respecting null vs 0 distinction */
export function formatRecordCount(count: number | null): string | null {
  if (count === null) return null;
  if (count === 0) return "0 records";
  return `${count.toLocaleString()} record${count === 1 ? "" : "s"}`;
}

/** Defang a URL/domain for safe display (standard practice) */
export function defang(value: string): string {
  return value
    .replace(/^https?:\/\//i, (m) => m.replace("http", "hxxp"))
    .replace(/\./g, "[.]");
}
