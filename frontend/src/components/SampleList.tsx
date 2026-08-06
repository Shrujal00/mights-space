import { Link } from "react-router-dom";

import { fileSize, timeAgo } from "../api/format";
import type { SampleSummary } from "../api/types";

interface Props {
  samples: SampleSummary[];
}

export default function SampleList({ samples }: Props) {
  if (samples.length === 0) {
    return (
      <section className="list">
        <div className="list__head">
          <h2 className="label">Examined</h2>
        </div>
        <p className="empty">
          Nothing examined yet. The first file you drop will appear here.
        </p>
      </section>
    );
  }

  return (
    <section className="list">
      <div className="list__head">
        <h2 className="label">Examined</h2>
        <span className="label">{samples.length}</span>
      </div>

      {samples.map((sample) => (
        <Link key={sample.id} to={`/samples/${sample.id}`} className="list__row">
          <span className="list__name">{sample.filename}</span>
          <span className="list__meta">
            {fileSize(sample.size)} · {timeAgo(sample.created_at)}
          </span>
          <VerdictTag sample={sample} />
        </Link>
      ))}
    </section>
  );
}

function VerdictTag({ sample }: { sample: SampleSummary }) {
  if (sample.status === "failed") {
    return <span className="tag tag--pending">Unreadable</span>;
  }
  if (sample.status !== "complete" || !sample.verdict) {
    return <span className="tag tag--pending">Reading</span>;
  }
  const label =
    sample.verdict === "unknown" ? "Nothing known" : sample.verdict;
  return <span className={`tag tag--${sample.verdict}`}>{label}</span>;
}
