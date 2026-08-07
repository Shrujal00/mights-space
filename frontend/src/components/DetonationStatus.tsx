import { useEffect, useRef } from "react";
import type { ProgressEntry } from "../api/types";

interface Props {
  platform: "android" | "windows";
  engine: "frida" | "speakeasy";
  progress: ProgressEntry[];
  done: boolean;
  failed?: boolean;
  error?: string;
}

/* Live lines from the sandbox itself. No invented stages — Android takes two
 * to three minutes, and the only honest thing to show is what the server
 * recorded while it worked. */
export default function DetonationStatus({
  platform,
  engine,
  progress,
  done,
  failed,
  error,
}: Props) {
  const endRef = useRef<HTMLLIElement | null>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [progress.length]);

  const platformContext =
    platform === "android"
      ? `Android sandbox · ${engine} instrumentation`
      : `Windows emulation · ${engine} · code never runs on this machine`;

  return (
    <section className="reading detonation" aria-live="polite">
      <div className="detonation__intro">
        <h2 className="detonation__title">
          {failed
            ? "Behavioural analysis stopped"
            : done
              ? "Behavioural analysis finished"
              : "Running behavioural analysis"}
        </h2>
        <p className="detonation__context">{platformContext}</p>
        {!done && !failed && (
          <p className="detonation__context">
            The file is being watched inside a contained sandbox. Nothing leaves
            this machine. This can take a few minutes — each line below is what
            the sandbox is doing right now.
          </p>
        )}
      </div>

      {failed && (
        <p className="notice" role="alert">
          Detonation was attempted and did not complete.
          {error ? ` ${error}` : ""}
        </p>
      )}

      {progress.length === 0 && !done && !failed ? (
        <p className="detonation__waiting">Starting the sandbox…</p>
      ) : (
        <ol className="detonation__log">
          {progress.map((entry, index) => {
            const isLatest = index === progress.length - 1 && !done && !failed;
            return (
              <li
                key={`${entry.at ?? "t"}-${index}`}
                ref={isLatest ? endRef : undefined}
                className={`detonation__line${isLatest ? " detonation__line--live" : ""}`}
              >
                <span className="detonation__when mono">
                  {formatWhen(entry.at)}
                </span>
                <span className="detonation__msg">{entry.message}</span>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function formatWhen(at: string | null): string {
  if (!at) return "—";
  const date = new Date(at);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}
