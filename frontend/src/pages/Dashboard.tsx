import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

import { ApiError, api } from "../api/client";
import { defang, fileSize, formatRecordCount, timeAgo } from "../api/format";
import type { BehaviorEvent, Health, Report, SampleSummary } from "../api/types";
import DropZone from "../components/DropZone";
import Section from "../components/Section";

const POLL_MS = 2000;

export default function Dashboard() {
  const navigate = useNavigate();
  const location = useLocation();
  const [samples, setSamples] = useState<SampleSummary[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [latest, setLatest] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hash = location.hash;
  const timer = useRef(0);

  const load = useCallback(async () => {
    const [nextHealth, nextSamples] = await Promise.all([
      api.health().catch(() => null),
      api.list().catch(() => [] as SampleSummary[]),
    ]);
    setHealth(nextHealth);
    setSamples(nextSamples);

    /* One report is pulled in full so the panels below can show real findings.
     * It is always the most recent analysis, and it is named wherever it is
     * shown — these panels describe that one file, never the whole caseload. */
    const newest = nextSamples.find(
      (sample) => sample.status === "detonating" || sample.status === "complete",
    );
    setLatest(newest ? await api.get(newest.id).catch(() => null) : null);

    return nextSamples;
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      const current = await load().catch(() => [] as SampleSummary[]);
      if (cancelled) return;
      /* Keep polling only while something is still moving. Scheduling from the
       * value just fetched, rather than from inside a state updater, keeps this
       * out of a render path where React would queue duplicate timers. */
      const working = current.some(
        (sample) => sample.status === "queued" || sample.status === "detonating",
      );
      if (working) timer.current = window.setTimeout(poll, POLL_MS);
    }

    void poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer.current);
    };
  }, [load]);

  useEffect(() => {
    if (!hash) return;
    document.getElementById(hash.slice(1))?.scrollIntoView({ behavior: "smooth" });
  }, [hash]);

  async function handleFile(file: File) {
    setBusy(true);
    setError(null);
    try {
      const receipt = await api.upload(file);
      navigate(`/samples/${receipt.id}`);
    } catch (cause) {
      setError(
        cause instanceof ApiError ? cause.message : "That file could not be accepted.",
      );
      setBusy(false);
    }
  }

  const { rows, title } = filterSamples(samples, hash);

  /* Every tile counts the whole caseload, from the list endpoint. Nothing here
   * is drawn from a single report — a figure labelled as a total has to be one. */
  const totals = {
    all: samples.length,
    malicious: samples.filter((s) => s.verdict === "malicious").length,
    suspicious: samples.filter((s) => s.verdict === "suspicious").length,
    working: samples.filter(
      (s) => s.status === "queued" || s.status === "detonating",
    ).length,
  };

  const runs = latest?.detonations ?? [];
  const observedRuns = runs.filter(
    (run) => run.status === "complete" || run.status === "timeout",
  );
  const reads = observedRuns
    .flatMap((run) => run.events)
    .filter((event) => event.category === "data-access");
  const exfiltration = observedRuns.flatMap((run) => run.exfiltration);

  return (
    <main className="page dash">
      {hash && (
        <div className="dash__filter-bar">
          <span className="label">Showing</span>
          <span className="chip chip--solid">{title}</span>
          <Link to="/" className="copy" style={{ marginLeft: "auto" }}>
            Clear
          </Link>
        </div>
      )}

      <section className="dash__overview">
        <Tile label="Files examined" value={totals.all} />
        <Tile label="Malicious" value={totals.malicious} />
        <Tile label="Suspicious" value={totals.suspicious} />
        <Tile label="In progress" value={totals.working} />
      </section>

      <div id="analyses">
        <DropZone busy={busy} error={error} onFile={handleFile} />
      </div>

      <div className="dash__grid">
        <div id="reports">
          <Section title={title} count={rows.length}>
            {rows.length === 0 ? (
              <p className="empty">Nothing here yet. Drop a file above to begin.</p>
            ) : (
              <div className="list">
                {rows.map((sample) => (
                  <Link
                    key={sample.id}
                    to={`/samples/${sample.id}`}
                    className="list__row"
                  >
                    <span className="list__name">{sample.filename}</span>
                    <span className="list__meta">
                      {fileSize(sample.size)} · {timeAgo(sample.created_at)}
                    </span>
                    <VerdictTag sample={sample} />
                  </Link>
                ))}
              </div>
            )}
          </Section>
        </div>

        {latest && (
          <>
            <div id="sandbox">
              {runs.length > 0 && (
                <Panel latest={latest} title="Sandbox runs" count={runs.length}>
                  {runs.map((run, index) => (
                    <div key={index} className="notice dash__run">
                      <p className="mono">
                        {run.platform} · {run.engine} · {run.status}
                      </p>
                      {run.status === "failed" ? (
                        <p className="dim dash__run-note">
                          Detonation did not complete, so nothing about this
                          file&rsquo;s behaviour was observed. {run.error}
                        </p>
                      ) : (
                        <p className="dim dash__run-note">{run.coverage}</p>
                      )}
                    </div>
                  ))}
                </Panel>
              )}
            </div>

            {reads.length > 0 && (
              <Panel latest={latest} title="Data it read" count={reads.length}>
                <div className="dash__table">
                  {reads.map((event, index) => (
                    <div key={index} className="dash__table-row">
                      <span className="label">{event.target}</span>
                      <span className="mono">{describeRead(event)}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            {exfiltration.length > 0 && (
              <Panel
                latest={latest}
                title="Data sent out of the device"
                count={exfiltration.length}
              >
                {exfiltration.map((finding, index) => (
                  <div key={index} className="notice dash__run">
                    <p className="mono" style={{ color: "var(--chalk)" }}>
                      {finding.what} → {defang(finding.where)}
                    </p>
                    <p className="dim dash__run-note">
                      {finding.gap_ms === null
                        ? `Sent afterwards · ${finding.confidence} pairing`
                        : `Sent ${(finding.gap_ms / 1000).toFixed(1)}s later · ${finding.confidence} pairing`}
                    </p>
                  </div>
                ))}
              </Panel>
            )}

            <div id="threats">
              <div id="iocs">
                {latest.indicators.length > 0 && (
                  <Panel
                    latest={latest}
                    title="Indicators"
                    count={latest.indicators.length}
                  >
                    <div>
                      {latest.indicators.map((indicator) => (
                        <div
                          key={`${indicator.type}:${indicator.value}`}
                          className="rowline"
                        >
                          <span className="mono">{defang(indicator.value)}</span>
                          <span className="label">{indicator.type}</span>
                        </div>
                      ))}
                    </div>
                  </Panel>
                )}
              </div>
            </div>

            <div id="static">
              {latest.techniques.length > 0 && (
                <Panel
                  latest={latest}
                  title="What it can do, from reading the code"
                  count={latest.techniques.length}
                >
                  <div className="cap">
                    {latest.techniques.map((technique) => (
                      <article key={technique.technique_id} className="cap__item">
                        <p className="cap__text">{technique.plain_language}</p>
                        <div className="cap__proof">
                          <span className="chip">{technique.technique_id}</span>
                        </div>
                      </article>
                    ))}
                  </div>
                  <p className="dim dash__run-note">
                    Read out of the code. Not behaviour that was observed.
                  </p>
                </Panel>
              )}
            </div>
          </>
        )}

        <div id="settings">
          {hash === "#settings" && health && (
            <Section title="System">
              <div className="notice">
                <p className="mono">
                  {health.offline_mode
                    ? "Air-gapped — no network lookups"
                    : "Connected — threat intelligence enabled"}
                </p>
                <p className="dim dash__run-note">
                  {health.yara_rules_loaded.toLocaleString()} signature files
                  loaded, {health.yara_rules_skipped} skipped.
                </p>
              </div>
            </Section>
          )}
        </div>

        <div id="docs">
          {hash === "#docs" && (
            <Section title="How to read these reports">
              <div className="notice">
                <p className="dim">
                  Capabilities are read out of a file&rsquo;s code and describe
                  what it is able to do. Observed behaviour is recorded while the
                  file runs in a contained sandbox and describes what it actually
                  did. The two are never merged. No file is ever described as
                  safe: an absence of findings is not a clearance.
                </p>
              </div>
            </Section>
          )}
        </div>
      </div>
    </main>
  );
}

/* A panel drawn from one report rather than from the whole caseload. The file it
 * describes is named on the panel, so no figure here can be mistaken for a
 * total across every analysis. */
function Panel({
  latest,
  title,
  count,
  children,
}: {
  latest: Report;
  title: string;
  count?: number;
  children: ReactNode;
}) {
  return (
    <Section title={title} count={count}>
      <p className="label dash__scope">Latest analysis · {latest.filename}</p>
      {children}
    </Section>
  );
}

function Tile({ label, value }: { label: string; value: number }) {
  return (
    <div className="stat">
      <span className="label">{label}</span>
      <p className="stat__val">{value}</p>
    </div>
  );
}

/* A read that came back empty took nothing, and a read that could not be counted
 * is not the same as one that returned zero. Both are said plainly. */
function describeRead(event: BehaviorEvent): string {
  return formatRecordCount(event.record_count) ?? "read";
}

function isAndroid(sample: SampleSummary): boolean {
  const type = sample.detected_type.toLowerCase();
  return type.includes("android") || type.includes("apk");
}

function filterSamples(samples: SampleSummary[], hash: string) {
  /* Filtering is on what the analysis found the file to be, never on its name —
   * a renamed .apk is exactly the kind of file this tool exists to catch. */
  switch (hash) {
    case "#android":
      return {
        rows: samples.filter((sample) => isAndroid(sample)),
        title: "Android applications",
      };
    case "#windows":
      return {
        rows: samples.filter(
          (sample) => sample.detected_type !== "" && !isAndroid(sample),
        ),
        title: "Windows programs and other files",
      };
    case "#reports":
      return {
        rows: samples.filter((sample) => sample.status === "complete"),
        title: "Completed reports",
      };
    case "#sandbox":
      return {
        rows: samples.filter((sample) => sample.status === "detonating"),
        title: "Running in the sandbox",
      };
    default:
      return { rows: samples, title: "Recent analyses" };
  }
}

function VerdictTag({ sample }: { sample: SampleSummary }) {
  if (sample.status === "failed") {
    return <span className="tag tag--pending">Unreadable</span>;
  }
  if (sample.status === "detonating") {
    return <span className="tag tag--pending">Running</span>;
  }
  if (sample.status !== "complete" || !sample.verdict) {
    return <span className="tag tag--pending">Reading</span>;
  }
  const label = sample.verdict === "unknown" ? "Nothing known" : sample.verdict;
  return <span className={`tag tag--${sample.verdict}`}>{label}</span>;
}
