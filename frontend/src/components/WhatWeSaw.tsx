import {
  absoluteDate,
  describeObservation,
  inferObservedPatterns,
} from "../api/format";
import type { DetonationRun } from "../api/types";

/** Plain-English summary of what the sandbox actually observed — for readers
 * who will not parse a technical timeline. */
export default function WhatWeSaw({ run }: { run: DetonationRun | null }) {
  if (!run || run.events.length + run.exfiltration.length === 0) {
    return null;
  }

  const patterns = inferObservedPatterns(run.events);
  const details: string[] = [];
  const seen = new Set<string>();

  for (const event of run.events) {
    const line = describeObservation(event);
    if (!seen.has(line)) {
      details.push(line);
      seen.add(line);
    }
  }

  for (const finding of run.exfiltration) {
    const line = `Stole ${finding.what} and sent it to ${finding.where}`;
    if (!seen.has(line)) {
      details.push(line);
      seen.add(line);
    }
  }

  const platform =
    run.platform === "windows"
      ? "emulated Windows sandbox"
      : "isolated Android phone";

  return (
    <section className="saw" aria-labelledby="saw-heading">
      <h2 id="saw-heading" className="saw__title">
        What we saw when this file ran
      </h2>
      <p className="saw__context dim">
        Observed in an {platform}
        {run.started_at ? ` · ${absoluteDate(run.started_at)}` : ""}
      </p>

      {patterns.length > 0 && (
        <div className="saw__patterns">
          {patterns.map((line) => (
            <p key={line} className="saw__lead">
              {line}
            </p>
          ))}
        </div>
      )}

      {details.length > 0 && (
        <>
          <p className="saw__detail-label label">Technical detail</p>
          <ul className="saw__list">
            {details.map((line) => (
              <li key={line} className="saw__item">
                {line}
              </li>
            ))}
          </ul>
        </>
      )}

      {run.coverage && <p className="saw__coverage dim">{run.coverage}</p>}

      <p className="saw__note dim">
        Static analysis of this file&apos;s code did not list specific
        capabilities — the file is small and hides what it does. The behaviour
        above was recorded only after it was run in the sandbox.
      </p>
    </section>
  );
}
