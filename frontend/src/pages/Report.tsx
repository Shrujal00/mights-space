import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { ApiError, api } from "../api/client";
import { absoluteDate, fileSize, shortType } from "../api/format";
import type { Report as ReportModel } from "../api/types";
import BehaviorTimeline from "../components/BehaviorTimeline";
import DetonationStatus from "../components/DetonationStatus";
import ReadingSequence from "../components/ReadingSequence";
import Section from "../components/Section";
import Verdict from "../components/Verdict";
import {
  AndroidApp,
  Capabilities,
  Contents,
  Destinations,
  Fingerprint,
  NotableStrings,
  Reasons,
  Signatures,
  Sources,
} from "../components/ReportSections";

const POLL_MS = 1200;

function WordButton({ id }: { id: number }) {
  const [state, setState] = useState<"idle" | "working" | "error">("idle");
  const [note, setNote] = useState<string | null>(null);

  async function download() {
    setState("working");
    setNote(null);
    try {
      const { narrative } = await api.downloadWord(id);
      setState("idle");
      if (narrative !== "ok") {
        setNote(
          narrative === "skipped"
            ? "Downloaded. No writing model configured, so the report uses the standard summary."
            : "Downloaded. The writing model couldn't be reached, so the report uses the standard summary.",
        );
      }
    } catch (cause) {
      setState("error");
      setNote(
        cause instanceof ApiError ? cause.message : "The report couldn't be built.",
      );
    }
  }

  return (
    <>
      <button
        type="button"
        className="btn btn--solid"
        onClick={download}
        disabled={state === "working"}
      >
        {state === "working" ? "Writing report…" : "Word report"}
      </button>
      {note && (
        <p className="report__note" role="status">
          {note}
        </p>
      )}
    </>
  );
}

export default function Report() {
  const { id } = useParams();
  const sampleId = Number(id);
  const [report, setReport] = useState<ReportModel | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!Number.isFinite(sampleId)) {
      setError("That sample reference isn't valid.");
      return;
    }

    let cancelled = false;
    let timer = 0;

    async function poll() {
      try {
        const next = await api.get(sampleId);
        if (cancelled) return;
        setReport(next);
        if (next.status === "queued" || next.status === "detonating") {
          timer = window.setTimeout(poll, POLL_MS);
        }
      } catch (cause) {
        if (cancelled) return;
        setError(
          cause instanceof ApiError ? cause.message : "Couldn't load the report.",
        );
      }
    }

    void poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [sampleId]);

  if (error) {
    return (
      <main className="page report">
        <div className="report__top">
          <Link to="/" className="back">
            ← All files
          </Link>
        </div>
        <p className="notice" role="alert">
          {error}
        </p>
      </main>
    );
  }

  if (!report) {
    return (
      <main className="page report">
        <div className="report__top">
          <Link to="/" className="back">
            ← All files
          </Link>
        </div>
        <p className="empty">Opening the report…</p>
      </main>
    );
  }

  const runningStatic = report.status === "queued";
  const runningDetonation = report.status === "detonating";
  const apps = report.files.filter((file) => file.is_apk);
  const strings = report.files.flatMap((file) => file.notable_strings ?? []);
  const paragraphs = (report.narrative ?? "").split("\n\n").filter(Boolean);
  const coda = paragraphs.at(-1) ?? null;
  const caveat =
    report.verdict === "unknown" && paragraphs.length >= 2
      ? paragraphs.at(-2)
      : null;

  const isApk = report.filename.endsWith(".apk") || report.files.some((f) => f.is_apk);
  const platform = isApk ? "android" : "windows";
  const engine = isApk ? "frida" : "speakeasy";

  /* Capabilities are always read out of the code — the backend deliberately
   * never writes a technique with a dynamic basis, because an inference and an
   * observation must not end up in the same list. What the sample was actually
   * seen doing lives in the timeline below, under its own heading. */
  const hasExecutedRun = report.detonations?.some(
    (d) => d.status === "complete" || d.status === "timeout"
  );

  return (
    <main className="page report">
      <div className="report__top">
        <Link to="/" className="back">
          ← All files
        </Link>
        {(report.status === "complete" || report.status === "detonating") && (
          <div className="report__actions">
            <a className="btn" href={api.exportUrl(report.id, "csv")} download>
              CSV
            </a>
            <a className="btn" href={api.exportUrl(report.id, "stix")} download>
              STIX
            </a>
            <WordButton id={report.id} />
          </div>
        )}
      </div>

      <header className="report__file">
        <h1 className="report__name">{report.filename}</h1>
        <p className="report__type">
          {shortType(report.detected_type)} · {fileSize(report.size)}
          {report.completed_at && ` · ${absoluteDate(report.completed_at)}`}
        </p>
      </header>

      {runningStatic && <ReadingSequence done={false} />}
      {runningDetonation && <DetonationStatus platform={platform} engine={engine} done={false} />}

      {report.status === "failed" && (
        <p className="notice" role="alert">
          This file couldn't be examined. {report.error ?? ""} The file is stored
          and can be examined again.
        </p>
      )}

      {(report.status === "complete" || report.status === "detonating") && report.verdict && (
        <>
          <Verdict level={report.verdict} headline={report.headline} />

          {caveat && (
            <div className="sec">
              <p className="notice">{caveat}</p>
            </div>
          )}

          {/* Sandbox Detonations */}
          {report.detonations && report.detonations.length > 0 && (
            <>
              {report.detonations.map((run, idx) => (
                <div key={idx} style={{ marginTop: "var(--s-12)" }}>
                  {run.status === "failed" && (
                    <Section title="Sandbox Detonation">
                      <p className="notice" role="alert">
                        Detonation failed: {run.error || "No error details available."}
                      </p>
                    </Section>
                  )}

                  {run.events && run.events.length > 0 && (
                    <Section title="Observed Behaviour Timeline" count={run.events.length}>
                      <BehaviorTimeline
                        events={run.events}
                        exfiltration={run.exfiltration}
                        timed={run.timed}
                        coverage={run.coverage}
                      />
                    </Section>
                  )}
                </div>
              ))}
            </>
          )}

          {report.reasons.length > 0 && (
            <Section title="Why" count={report.reasons.length}>
              <Reasons reasons={report.reasons} />
            </Section>
          )}

          {apps.map((app) => (
            <Section key={app.sha256} title="The app behind the name">
              <AndroidApp app={app} />
            </Section>
          ))}

          {report.techniques.length > 0 && (
            <Section
              title="What it can do, from reading the code"
              count={report.techniques.length}
            >
              <Capabilities techniques={report.techniques} />
              <p className="dim" style={{ marginTop: "var(--s-4)" }}>
                These describe what the file is able to do, read out of its code.
                They are not behaviour that was observed.
              </p>
            </Section>
          )}

          {report.indicators.length > 0 && (
            <Section title="Where it connects" count={report.indicators.length}>
              <Destinations indicators={report.indicators} />
            </Section>
          )}

          {report.yara.length > 0 && (
            <Section title="Matched signatures" count={report.yara.length}>
              <Signatures hits={report.yara} />
            </Section>
          )}

          {report.files.length > 0 && (
            <Section title="What's inside" count={report.files.length}>
              <Contents files={report.files} />
            </Section>
          )}

          {strings.length > 0 && (
            <Section title="Notable text found inside" count={strings.length}>
              <NotableStrings strings={strings} />
            </Section>
          )}

          <Section title="Fingerprint">
            <Fingerprint
              values={[
                { label: "SHA-256", value: report.sha256 },
                { label: "SHA-1", value: report.sha1 },
                { label: "MD5", value: report.md5 },
              ]}
            />
          </Section>

          {report.providers.length > 0 && (
            <Section title="Who we asked" count={report.providers.length}>
              <Sources providers={report.providers} />
            </Section>
          )}

          {report.warnings.length > 0 && (
            <Section title="Notes on reading this file" count={report.warnings.length}>
              {report.warnings.map((warning) => (
                <p key={warning} className="notice">
                  {warning}
                </p>
              ))}
            </Section>
          )}

          {coda && <p className="coda">{coda}</p>}

          <footer className="foot">
            {hasExecutedRun
              ? "Executed in a contained sandbox · Dynamic & static analysis"
              : "Files are read, never run · Static analysis only"}
          </footer>
        </>
      )}
    </main>
  );
}
