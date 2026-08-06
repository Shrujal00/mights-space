import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { api } from "../api/client";
import type { Health } from "../api/types";

/* The rail reports the two facts that change how much a report can be trusted:
 * whether the tool is allowed to ask the internet anything, and how many
 * signatures it is matching against. Both are otherwise invisible. */
export default function StatusRail() {
  const [health, setHealth] = useState<Health | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .health()
      .then((value) => {
        if (!cancelled) setHealth(value);
      })
      .catch(() => {
        if (!cancelled) setHealth(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <header className="rail">
      <div className="page rail__inner">
        <Link to="/" className="rail__mark">
          Static Triage
        </Link>

        {health && (
          <div className="rail__stats">
            <span className="rail__stat label" title={rulesTitle(health)}>
              <span className="rail__ring rail__ring--on" aria-hidden="true" />
              {health.yara_rules_loaded.toLocaleString()} signatures
            </span>
            {/* "Offline" would read as a fault. Air-gapped operation is a
                deliberate mode, and it changes how complete a report can be, so
                it is named as a choice and explained on hover. */}
            <span
              className="rail__stat label rail__stat--optional"
              title={
                health.offline_mode
                  ? "No lookups leave this machine. Reports use local analysis only."
                  : "Hashes and indicators are checked against threat-intelligence sources."
              }
            >
              <span
                className={
                  health.offline_mode ? "rail__ring" : "rail__ring rail__ring--on"
                }
                aria-hidden="true"
              />
              {health.offline_mode ? "Air-gapped" : "Connected"}
            </span>
          </div>
        )}
      </div>
    </header>
  );
}

function rulesTitle(health: Health): string {
  if (health.yara_rules_skipped === 0) {
    return "All signature files loaded.";
  }
  return `${health.yara_rules_skipped} signature file(s) could not be loaded.`;
}
