import { useEffect, useState } from "react";

const ANDROID_STAGES = [
  ["Preparing", "Setting up the sandbox environment"],
  ["Booting", "Starting the Android emulator"],
  ["Installing", "Loading the application into the sandbox"],
  ["Instrumenting", "Attaching behaviour monitors"],
  ["Observing", "Watching what the application does"],
  ["Collecting", "Gathering observations"],
  ["Correlating", "Pairing data access with network activity"],
] as const;

const WINDOWS_STAGES = [
  ["Loading", "Reading the executable into the emulator"],
  ["Emulating", "Running instructions in a contained CPU"],
  ["Mapping", "Matching API calls to known techniques"],
  ["Collecting", "Gathering observations"],
] as const;

interface Props {
  platform: "android" | "windows";
  engine: "frida" | "speakeasy";
  done: boolean;
  failed?: boolean;
  error?: string;
}

export default function DetonationStatus({ platform, engine, done, failed, error }: Props) {
  const [reached, setReached] = useState(0);

  const stages = platform === "android" ? ANDROID_STAGES : WINDOWS_STAGES;
  const stepMs = platform === "android" ? 4000 : 3000;

  useEffect(() => {
    if (done || failed) return;
    const timer = window.setInterval(() => {
      // Hold on the final stage until the server actually answers
      setReached((current) => Math.min(current + 1, stages.length - 1));
    }, stepMs);
    return () => window.clearInterval(timer);
  }, [done, failed, stages.length, stepMs]);

  const platformContext =
    platform === "android"
      ? `Android sandbox · ${engine} instrumentation`
      : `Windows emulation · ${engine} engine · Code never executes natively`;

  return (
    <section className="reading" aria-live="polite">
      <div style={{ marginBottom: "var(--s-8)" }}>
        <h2 style={{ 
          fontFamily: "var(--display)", 
          fontSize: "var(--t-lead)", 
          color: "var(--chalk)", 
          margin: "0 0 var(--s-2) 0",
          fontWeight: 600
        }}>
          Sandbox detonation
        </h2>
        <div style={{ 
          color: "var(--muted)", 
          fontSize: "var(--t-small)",
          fontFamily: "var(--body)"
        }}>
          <p style={{ margin: "0 0 var(--s-1) 0" }}>{platformContext}</p>
          <p style={{ margin: 0 }}>The file is being executed in a contained sandbox. Nothing leaves the machine.</p>
        </div>
      </div>

      {failed && (
        <div style={{ 
          padding: "var(--s-4)", 
          border: "1px solid var(--pure)", 
          background: "var(--surface)", 
          color: "var(--chalk)", 
          marginBottom: "var(--s-6)" 
        }}>
          <strong style={{ 
            display: "block", 
            fontFamily: "var(--mono)", 
            textTransform: "uppercase", 
            fontSize: "var(--t-small)", 
            letterSpacing: "0.1em",
            marginBottom: "var(--s-2)" 
          }}>
            Detonation Failed
          </strong>
          <span style={{ fontSize: "var(--t-small)", color: "var(--muted)" }}>
            {error || "An unknown error occurred during detonation."}
          </span>
        </div>
      )}

      {stages.map(([name, description], index) => {
        const state = done ? "done" : failed && index >= reached ? "waiting" : index < reached ? "done" : index === reached ? "active" : "waiting";
        return (
          <div key={name} className={`reading__row reading__row--${state}`}>
            <span className="reading__name">{name}</span>
            <span className="reading__state">
              {state === "done" ? "Done" : state === "active" ? description : ""}
            </span>
            <span className="reading__fill" aria-hidden="true" />
          </div>
        );
      })}
    </section>
  );
}
