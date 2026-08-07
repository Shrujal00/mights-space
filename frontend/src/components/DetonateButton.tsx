import { useState } from "react";
import { ApiError, api } from "../api/client";

interface Props {
  sampleId: number;
  onStarted: () => void;
}

/* The deliberate step from reading a file to running it. Shown only when the
 * report says this server can detonate this sample. */
export default function DetonateButton({ sampleId, onStarted }: Props) {
  const [state, setState] = useState<"idle" | "working" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  async function start() {
    setState("working");
    setError(null);
    try {
      await api.detonate(sampleId);
      setState("idle");
      onStarted();
    } catch (cause) {
      setState("error");
      setError(
        cause instanceof ApiError
          ? cause.message
          : "The sandbox could not be started.",
      );
    }
  }

  return (
    <section className="detonate">
      <h2 className="detonate__title">Behavioural analysis</h2>
      <p className="detonate__copy">
        Static analysis is finished. You can now run this file in a contained
        sandbox to see what it actually does — what data it reads, and where it
        tries to send it. Nothing leaves this machine. Android runs take about
        two to three minutes.
      </p>
      <button
        type="button"
        className="btn btn--solid"
        onClick={start}
        disabled={state === "working"}
      >
        {state === "working" ? "Starting sandbox…" : "Run behavioural analysis"}
      </button>
      {error && (
        <p className="notice" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
