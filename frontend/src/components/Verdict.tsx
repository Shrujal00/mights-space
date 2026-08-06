import type { Verdict as VerdictLevel } from "../api/types";

/* Severity is carried by fill, not hue. Malicious inverts the page to solid
 * white — the single loudest thing the interface can do, and reserved for the
 * one finding that justifies it. Suspicious is outlined, unknown is a hairline.
 * Nothing renders as "clear", because the analysis cannot establish that. */
const WORDS: Record<VerdictLevel, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  unknown: "Nothing known",
};

interface Props {
  level: VerdictLevel;
  headline: string | null;
}

export default function Verdict({ level, headline }: Props) {
  return (
    <section className={`verdict verdict--${level}`}>
      <p className="label" style={{ color: "inherit", opacity: 0.6 }}>
        Assessment
      </p>
      <h2 className="verdict__word">{WORDS[level]}</h2>
      {headline && <p className="verdict__line">{headline}</p>}
    </section>
  );
}
