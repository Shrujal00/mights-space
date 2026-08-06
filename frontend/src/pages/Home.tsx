import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { ApiError, api } from "../api/client";
import type { SampleSummary } from "../api/types";
import DropZone from "../components/DropZone";
import SampleList from "../components/SampleList";

export default function Home() {
  const navigate = useNavigate();
  const [samples, setSamples] = useState<SampleSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setSamples(await api.list());
    } catch {
      /* The list is context, not the task. A failure here stays quiet — the
         drop zone reports anything that blocks the actual work. */
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleFile(file: File) {
    setBusy(true);
    setError(null);
    try {
      const receipt = await api.upload(file);
      navigate(`/samples/${receipt.id}`);
    } catch (cause) {
      setError(
        cause instanceof ApiError
          ? cause.message
          : "That file could not be accepted.",
      );
      setBusy(false);
    }
  }

  return (
    <main className="page report">
      <section className="hero">
        {/* Two fixed lines rather than a wrapping paragraph: at display size a
            natural break lands wherever the viewport decides, and the second
            clause is the whole promise — it has to survive intact. */}
        <h1 className="hero__thesis">
          <span className="hero__line">Every file is read.</span>
          <span className="hero__line hero__line--quiet">Never run.</span>
        </h1>
        <p className="hero__sub">
          Drop in something suspicious. You'll get a plain-English answer you can
          put in a case file — and the evidence behind it.
        </p>
      </section>

      <DropZone busy={busy} error={error} onFile={handleFile} />

      <SampleList samples={samples} />
    </main>
  );
}
