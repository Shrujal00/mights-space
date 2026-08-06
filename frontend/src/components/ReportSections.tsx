import { useState } from "react";

import {
  INDICATOR_LABELS,
  PROVIDER_LABELS,
  PROVIDER_STATE_LABELS,
  fileSize,
  withoutCan,
} from "../api/format";
import type {
  Indicator,
  LeafFile,
  NotableString,
  ProviderStatus,
  Technique,
  YaraHit,
} from "../api/types";

/* Why ---------------------------------------------------------------------- */

export function Reasons({ reasons }: { reasons: string[] }) {
  return (
    <div>
      {reasons.map((reason) => (
        <p key={reason} className="why__item">
          <span className="why__mark" aria-hidden="true" />
          <span>{reason}</span>
        </p>
      ))}
    </div>
  );
}

/* What it can do ----------------------------------------------------------- */

export function Capabilities({ techniques }: { techniques: Technique[] }) {
  return (
    <div className="cap">
      {techniques.map((technique) => (
        <article key={technique.technique_id} className="cap__item">
          <p className="cap__text">{withoutCan(technique.plain_language)}</p>
          <div className="cap__proof">
            <span className="chip" title={technique.name}>
              {technique.technique_id}
            </span>
            {technique.basis === "dynamic-observed" && (
              <span className="chip" style={{ background: "var(--pure)", color: "var(--void)", fontWeight: 600 }}>
                OBSERVED
              </span>
            )}
            {technique.evidence.slice(0, 4).map((name) => (
              <span key={name} className="chip">
                {name}
              </span>
            ))}
            {technique.evidence.length > 4 && (
              <span className="chip">+{technique.evidence.length - 4}</span>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}

/* Where it connects -------------------------------------------------------- */

export function Destinations({ indicators }: { indicators: Indicator[] }) {
  return (
    <div>
      {indicators.map((indicator) => (
        <div key={`${indicator.type}:${indicator.value}`} className="dest__row">
          <div className="dest__facts">
            <span className="label">
              {INDICATOR_LABELS[indicator.type] ?? indicator.type}
            </span>
            {indicator.threatfox?.malware && (
              <span className="dest__flag">
                Known {indicator.threatfox.threat_type === "botnet_cc"
                  ? "control server"
                  : "malicious host"}
              </span>
            )}
          </div>

          <p className="dest__value">{indicator.value}</p>

          <div className="dest__facts">
            {indicator.threatfox?.malware && (
              <span className="dest__fact">
                <span className="label">Used by</span>
                <span className="mono">{indicator.threatfox.malware}</span>
              </span>
            )}

            {typeof indicator.abuseipdb?.abuse_confidence === "number" && (
              <span className="dest__fact">
                <span className="label">Reported</span>
                <span className="meter" aria-hidden="true">
                  <span
                    className="meter__fill"
                    style={{
                      transform: `scaleX(${indicator.abuseipdb.abuse_confidence / 100})`,
                    }}
                  />
                </span>
                <span className="mono">
                  {indicator.abuseipdb.abuse_confidence}%
                </span>
                {indicator.abuseipdb.country && (
                  <span className="mono dim">{indicator.abuseipdb.country}</span>
                )}
              </span>
            )}

            {typeof indicator.urlscan?.result_count === "number" &&
              indicator.urlscan.result_count > 0 && (
                <span className="dest__fact">
                  <span className="label">Seen before</span>
                  <span className="mono">
                    {indicator.urlscan.result_count} scan
                    {indicator.urlscan.result_count === 1 ? "" : "s"}
                  </span>
                </span>
              )}
          </div>
        </div>
      ))}
    </div>
  );
}

/* Matched signatures ------------------------------------------------------- */

export function Signatures({ hits }: { hits: YaraHit[] }) {
  return (
    <div>
      {hits.map((hit, index) => (
        <div key={`${hit.rule}-${index}`} className="rowline">
          <span className="rowline__main">{hit.rule}</span>
          <span className="rowline__note">
            {hit.meta.description ?? hit.tags.join(" · ") ?? ""}
          </span>
        </div>
      ))}
    </div>
  );
}

/* What's inside ------------------------------------------------------------ */

export function Contents({ files }: { files: LeafFile[] }) {
  return (
    <div>
      {files.map((file) => (
        <article key={file.sha256 + file.relative_name} className="file">
          <div className="file__head">
            <span className="file__name">{file.relative_name}</span>
            <span className="label">{fileSize(file.size)}</span>
            {file.machine && <span className="label">{file.machine}</span>}
            {file.likely_packed && (
              <span
                className="dest__flag"
                title={file.packing_reasons.join("; ")}
              >
                Concealed
              </span>
            )}
          </div>

          <p className="rowline__note">{file.detected_type}</p>

          {file.sections.length > 0 && (
            <div className="file__sections">
              {file.sections.map((section) => (
                <div key={section.name} className="file__section">
                  <span>{section.name}</span>
                  <span className="meter" aria-hidden="true">
                    <span
                      className="meter__fill"
                      style={{ transform: `scaleX(${section.entropy / 8})` }}
                    />
                  </span>
                  <span title="Randomness, 0 to 8. High values suggest compressed or encrypted content.">
                    {section.entropy.toFixed(1)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </article>
      ))}
    </div>
  );
}

/* Fingerprint -------------------------------------------------------------- */

export function Fingerprint({
  values,
}: {
  values: { label: string; value: string }[];
}) {
  return (
    <div className="print">
      {values.map((entry) => (
        <div key={entry.label} className="print__row">
          <span className="label">{entry.label}</span>
          <span className="print__value">
            {entry.value} <CopyButton value={entry.value} />
          </span>
        </div>
      ))}
    </div>
  );
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      type="button"
      className="copy"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1600);
        } catch {
          setCopied(false);
        }
      }}
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/* Who we asked ------------------------------------------------------------- */

export function Sources({ providers }: { providers: ProviderStatus[] }) {
  return (
    <div className="sources">
      {providers.map((provider) => (
        <div key={provider.provider} className="source">
          <span className="source__name">
            {PROVIDER_LABELS[provider.provider] ?? provider.provider}
            {provider.detail && (
              <span className="rowline__note"> — {provider.detail}</span>
            )}
          </span>
          <span
            className={
              provider.status === "ok"
                ? "source__state source__state--ok"
                : "source__state"
            }
          >
            {PROVIDER_STATE_LABELS[provider.status] ?? provider.status}
          </span>
        </div>
      ))}
    </div>
  );
}

/* The app is not who it says it is ---------------------------------------- */

export function AndroidApp({ app }: { app: LeafFile }) {
  return (
    <article className="apk">
      {/* The mismatch between these two lines is the finding. Presenting them
          adjacent, in the same weight, is what makes it obvious. */}
      <div className="apk__identity">
        <div className="apk__claim">
          <span className="label">Presents itself as</span>
          <p className="apk__label">{app.app_label || "(no name)"}</p>
        </div>
        <div className="apk__claim">
          <span className="label">Published under</span>
          <p className="apk__package">{app.package ?? "unknown"}</p>
        </div>
      </div>

      {app.signals.length > 0 && (
        <div className="apk__signals">
          {app.signals.map((signal) => (
            <div key={signal.code} className="apk__signal">
              <p className="apk__signalText">{signal.plain_language}</p>
              <p className="apk__signalDetail mono">{signal.detail}</p>
            </div>
          ))}
        </div>
      )}

      <PermissionGroup
        title="Reaches personal data"
        permissions={app.dangerous_permissions}
      />
      <PermissionGroup
        title="Commonly abused for fraud"
        permissions={app.high_abuse_permissions}
      />

      {app.certificates.map((certificate) => (
        <div key={certificate.sha256} className="apk__cert">
          <span className="label">Signing fingerprint</span>
          <p className="mono">{certificate.sha256}</p>
          <p className="rowline__note">
            Apps from one campaign are usually signed with the same key, even
            when their names differ. Worth comparing against other exhibits.
          </p>
        </div>
      ))}
    </article>
  );
}

function PermissionGroup({
  title,
  permissions,
}: {
  title: string;
  permissions: string[];
}) {
  if (permissions.length === 0) return null;
  return (
    <div className="apk__perms">
      <span className="label">{title}</span>
      <div className="apk__chips">
        {permissions.map((permission) => (
          <span key={permission} className="chip">
            {permission.replace("android.permission.", "")}
          </span>
        ))}
      </div>
    </div>
  );
}

/* Suspicious strings ------------------------------------------------------- */

export function NotableStrings({ strings }: { strings: NotableString[] }) {
  const grouped = new Map<string, NotableString[]>();
  for (const item of strings) {
    grouped.set(item.category, [...(grouped.get(item.category) ?? []), item]);
  }

  return (
    <div>
      {[...grouped.entries()].map(([category, items]) => (
        <div key={category} className="strings__group">
          <div className="strings__head">
            <span className="label">{category}</span>
            <span className="rowline__note">{items[0].why}</span>
          </div>
          {items.map((item) => (
            <p key={item.value} className="strings__value mono">
              {item.value}
            </p>
          ))}
        </div>
      ))}
    </div>
  );
}
