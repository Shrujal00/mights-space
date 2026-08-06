import { useEffect, useState } from "react";

/* The real stages of app/analysis/pipeline.py, in the order the backend runs
 * them. The API reports only "queued" then "complete", so these advance on a
 * timer and hold at the last stage until the server actually answers — the
 * sequence shows what is being done, and never claims a stage finished early. */
const STAGES = [
  ["Fingerprinting", "Hashing the file"],
  ["Unpacking", "Expanding archives"],
  ["Matching", "Comparing against known signatures"],
  ["Structure", "Reading the program's layout"],
  ["Text", "Recovering readable text"],
  ["Addresses", "Finding internet addresses"],
  ["Intelligence", "Checking sources"],
] as const;

const STEP_MS = 900;

interface Props {
  done: boolean;
}

export default function ReadingSequence({ done }: Props) {
  const [reached, setReached] = useState(0);

  useEffect(() => {
    if (done) return;
    const timer = window.setInterval(() => {
      // Hold on the final stage: the server, not the clock, decides when the
      // analysis is finished.
      setReached((current) => Math.min(current + 1, STAGES.length - 1));
    }, STEP_MS);
    return () => window.clearInterval(timer);
  }, [done]);

  return (
    <section className="reading" aria-live="polite">
      <h2 className="visually-hidden">Analysis progress</h2>
      {STAGES.map(([name, description], index) => {
        const state = done || index < reached ? "done" : index === reached ? "active" : "waiting";
        return (
          <div key={name} className={`reading__row reading__row--${state}`}>
            <span className="reading__name">{name}</span>
            <span className="reading__state">
              {state === "done" ? "Read" : state === "active" ? description : ""}
            </span>
            <span className="reading__fill" aria-hidden="true" />
          </div>
        );
      })}
    </section>
  );
}
