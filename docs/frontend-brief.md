# Frontend brief: the dynamic analysis interface

**A prompt for the agent building this.** Read the whole thing before writing
code. The hard part of this task is not the layout — it is knowing which parts
of the reference mockup are backed by real data and which would be fabrication.

---

## What you are building on

`frontend/` is an existing, working Vite + React + TypeScript app. Do not
scaffold a new one.

```
frontend/src/
  App.tsx                  routes: "/" and "/samples/:id", plus StatusRail + footer
  main.tsx
  api/
    client.ts              fetch wrappers
    types.ts               mirrors the backend response shapes — CURRENTLY STALE
    format.ts              display formatting helpers
  components/
    StatusRail.tsx         offline / health indicator
    DropZone.tsx           upload
    SampleList.tsx         list of analyses
    ReadingSequence.tsx    the "analysis in progress" pattern — reuse this
    Verdict.tsx            the assessment block
    Section.tsx            section wrapper
    ReportSections.tsx     report body
  pages/
    Home.tsx  Report.tsx
  styles/
    tokens.css  base.css  app.css
```

A design skill is vendored at `.agents/skills/hallmark/` and pinned in
`skills-lock.json`. Use it.

Backend runs on `:8000`, dev server on `:5173`, and the backend's CORS already
allows that origin. Under Compose the dev server proxies `/api` to
`http://backend:8000`.

---

## The design system is not up for negotiation

`src/styles/tokens.css` is **strictly achromatic — there is not one hue in the
file**, and that is a product decision, not a stylistic one. Its own comment
explains why, and it is the single most important constraint in this brief:

> The backend refuses to describe any file as safe, because static analysis
> cannot prove the absence of harm. A traffic-light interface would undo that:
> green reads as "cleared."

So severity is carried by **value and inversion**, never by hue. `Verdict.tsx`
already establishes the vocabulary: malicious inverts to solid white, suspicious
is outlined, unknown is a hairline, and nothing ever renders as "clear."

**The reference mockup is saturated with colour — green, red, amber, blue. Do
not carry any of it across.** Take the mockup's *layout and information
architecture*; render all of it in the existing monochrome system.

The tokens you have: `--void --surface --edge --muted --chalk --pure` for
value; `--display` (Archivo Variable, `font-stretch` 112–118%), `--body` (IBM
Plex Sans), `--mono` (IBM Plex Mono) for type; a 4px rhythm (`--s-*`); one
easing curve (`--ease`) so everything that moves shares a physical character.
Fonts are self-hosted via `@fontsource` — **never add a CDN link**, it would
break air-gapped deployment, which is a supported mode.

Add no new colour tokens. If you need another step, add a neutral one.

---

## What to remove from the mockup, and why

This is the part that matters most. Each of these appears in the reference and
**must not be built**, because the backend cannot produce the data honestly.

| Remove | Why |
|---|---|
| **"Risk Score 92/100"** | No numeric score exists anywhere in the system. The verdict is exactly three values: `malicious`, `suspicious`, `unknown`. A number out of 100 implies a calibrated model that was never built, and it is the single most indefensible thing you could put in a police report. |
| **Radar / spider "Behavior Summary"** | A radar chart needs a magnitude per axis (Data Theft 85, Keylogging 40…). Those values do not exist and cannot be derived. |
| **HIGH / MEDIUM / LOW badges on capabilities** | `Technique` has `technique_id`, `name`, `plain_language`, `evidence`, `basis`. There is no severity field. Replace this column with the static-vs-observed distinction, which is real and matters far more. |
| **World map with connection arcs** | The only geography available is an optional `country` string from AbuseIPDB. Arcs between points imply routing and geolocation the system does not have. |
| **Sandbox pool — "Active Sandboxes 3/5", Windows_1, Android_1…3** | Detonations are **serialised by design**: one sample at a time. The host has 15 GB and two concurrent sandboxes do not fit. There is no pool, and there are no named instances. |
| **"Sandbox: Android_1" on each analysis row** | Same reason — no instance names exist. |
| **Notification bell with a badge** | There is no notification system. |
| **"Investigating Officer / Cyber Crime Unit" chip and avatar** | There is no auth, no users, no roles. |
| **"Cases" nav item** | There is no case model in the backend. |
| **"Audit Logs" nav item** | There is no audit log. |
| **"All systems secure"** | Meaningless, and it is a safety claim — precisely the kind this product refuses to make. Replace with facts: YARA rules loaded/skipped and offline mode, both from `/api/health`. |
| **"32 Connections" per destination** | Not counted for static reports. For a detonated sample you *may* count `network` events sharing a target — but only render it when it is real. |
| **High/Medium/Low column in "Data Accessed"** | The counts are real; the severity is invented. Keep the counts, drop the column. |
| **Sparklines in the stat tiles** | Only build these if you genuinely derive them from `created_at` over time. Do not ship a decorative shape that implies a trend. When in doubt, leave them out. |

The general rule, from the plan: **build only panels backed by real data.** If a
panel would need a number the API does not return, the panel does not ship.

---

## What to keep from the mockup

The overall shape is good and the user wants it: a persistent left rail, a dense
overview grid at the top, then panels below.

- **Left rail** — Dashboard, Analysis Center, Static Analysis, Dynamic Sandbox,
  Android Analysis, Windows Analysis, Reports, IOC Feed, Threat Intelligence,
  Settings, Help & Docs. Drop Cases and Audit Logs. Keep the crest, the
  air-gapped indicator and a factual system-status block at the bottom.
- **Overview stat tiles** — Total analyses, malicious verdicts, IOCs extracted,
  files examined. All countable from existing endpoints.
- **Recent analyses** — filename, file-type badge, verdict, relative time. No
  score, no sandbox name.
- **Capabilities + MITRE chips** — real, from `techniques[]`.
- **Data accessed** — real, and the best panel in the mockup. See below.
- **Threat intelligence list** — real, from `indicators[]`. Keep the defanged
  notation (`api.loanverify[.]ru`, `hxxps://`); it is correct practice.
- **Exfiltration destinations** — real, from `exfiltration[]`, as a list.

---

## The API you are building against

`src/api/types.ts` says at the top that it "mirrors `app/api/samples.py` exactly
— every field here is one the API actually sends." **That is currently false.**
It predates dynamic analysis. Your first job is to bring it back in line.

Endpoints:

```
GET  /api/health                      { status, offline_mode, yara_rules_loaded, yara_rules_skipped }
GET  /api/samples                     SampleSummary[]
POST /api/samples                     multipart "file" → { id, sha256, status, duplicate }
GET  /api/samples/{id}                Report
GET  /api/samples/{id}/export.csv
GET  /api/samples/{id}/export.stix
GET  /api/samples/{id}/export.docx    also sets an X-Narrative-Status header
```

Two changes to existing types:

```ts
// "detonating" is new — a sample is running in a sandbox.
export type SampleStatus = "queued" | "detonating" | "complete" | "failed";

export interface Report {
  /* …everything already there… */
  detonations: DetonationRun[];   // NEW; empty array for a static-only report
}
```

And the new shapes:

```ts
export type EventCategory =
  | "process" | "file" | "network" | "data-access" | "registry" | "crypto";

export interface BehaviorEvent {
  at: string | null;          // ISO
  offset_ms: number;          // milliseconds since the app was launched
  category: EventCategory;
  action: string;             // "read", "sent", "started", "wrote", "called"
  target: string;             // "SMS inbox", "185.244.25.14:443"
  detail: string;             // "247 records"
  source: string;             // "frida" | "speakeasy"
  size_bytes: number | null;  // null = not measured, NOT zero
  record_count: number | null;// null = not counted, NOT zero
  basis: "dynamic-observed";
}

export interface ExfiltrationFinding {
  what: string;               // "247 records from SMS inbox"
  where: string;              // "185.244.25.14:443"
  when: string | null;
  gap_ms: number | null;      // null when the engine had no clock
  bytes_sent: number | null;
  confidence: "strong" | "probable";
}

export interface DetonationRun {
  platform: "android" | "windows";
  engine: "frida" | "speakeasy";
  status: "queued" | "running" | "complete" | "failed" | "timeout";
  started_at: string | null;
  finished_at: string | null;
  error: string;
  timed: boolean;             // false = order only, no clock
  coverage: string;           // the conditions the run was made under
  artifacts: Record<string, string>;
  events: BehaviorEvent[];
  exfiltration: ExfiltrationFinding[];
}
```

Dynamic analysis is **off by default** (`DYNAMIC_ANALYSIS_ENABLED`), so
`detonations` is very often `[]`. A static-only report must remain a complete,
first-class report — not a page full of empty panels.

---

## The three things the plan actually asks you to add

### 1. The behaviour timeline — the centrepiece

Vertical. One row per event. Monospace offsets in the left column. Category as a
quiet mono label. This is the panel the whole dynamic pipeline exists to
produce, and it should read like a sequence of events, not a table dump.

A real run looks like this:

```
+0.05s   process       started   the application
+0.46s   data-access   read      SMS inbox            2 records
+0.49s   data-access   read      contacts             0 records
+3.61s   network       opened    http://10.0.2.2:8099/collect
```

**Data-access and network events that are adjacent in time must be visually
linked** — a bracket, a spine, a connecting rule down the gutter. That pairing
*is* the exfiltration finding, and the timeline should let a reader see it
before they read the words.

Two rules you must not break:

- **When `timed` is `false`, do not render offsets.** The Windows emulator
  reports the order of calls and nothing else. Number the steps 1, 2, 3 and say
  the entries are in order rather than to a clock. Printing `+0.0s` against
  every row would imply measurements that were never taken.
- **`record_count: 0` and `record_count: null` are different facts.** Zero means
  the query came back empty. Null means it could not be counted (reading a
  device identifier returns no row count). Never render null as `0`.

### 2. Detonation status

`ReadingSequence.tsx` already does this for static analysis — extend the same
pattern rather than inventing a second one. A sample moves
`queued → detonating → complete`, and an Android detonation takes **two to three
minutes**: roughly 40 seconds of emulator boot, install, 40 seconds of dwell,
then shutdown. That is a long silence, so this component is doing real work.
Show what stage it is at.

One panel for the current run. Not a grid of five.

### 3. Static versus observed — never merge the two lists

This is the invariant the whole report rests on. A capability is an inference
drawn from reading code; an observation is a record of something that happened.
They carry completely different evidential weight and a document that blurs them
falls apart the first time it is challenged.

```
Capability (from reading the code):   can read text messages
Observed (sandbox, +0.46s):           read 2 text messages
```

Give observed entries a distinct treatment — a mono `OBSERVED` marker with the
offset is suggested. Every dynamic event carries `basis: "dynamic-observed"`;
static techniques carry `static-import` or `static-manifest`. Use it, and keep
the two in separate sections with separate headings.

---

## Honesty requirements

These are not polish. Getting one wrong makes the output indefensible.

1. **Fix the footer.** `App.tsx` currently ends every page with *"Files are read,
   never run · Static analysis only."* That is false for any detonated sample.
   Make it conditional on whether the report has an executed run, exactly as the
   backend made its `NOT_EXECUTED_NOTE` conditional.

2. **Render `coverage` prominently on every run.** It states the conditions the
   observations were made under — that the sandbox granted the permissions the
   app asked for, that the phone was seeded with decoy messages, how long it
   ran, and that behaviour which waits for a real person would not appear. An
   observation without its conditions is not evidence. Do not tuck it in a
   tooltip.

3. **A failed detonation is not a quiet one.** When `status` is `failed`, show
   that detonation was attempted and show `error`. An empty timeline and an
   unobserved app must never look the same on screen.

4. **Never invent a number.** Every figure rendered must come from a field.
   No score, no percentage, no severity, no synthesised trend.

5. **Nothing is ever "clean", "safe", or "cleared".** `unknown` means no known
   indicators were found, which is not the same as harmless.

---

## Definition of done

- `types.ts` matches `app/api/samples.py` again, including `detonations` and the
  `detonating` status.
- A static-only report renders exactly as well as it does today.
- A detonated report shows the timeline, the exfiltration findings, the run
  conditions, and the static/observed split.
- A failed detonation shows why it failed.
- `timed: false` renders as ordered steps with no timestamps.
- Not one hue anywhere in the diff. `grep` the stylesheet and check.
- Layout holds from roughly 1280px up; the dense grid may stack below that.
- `npm run build` passes with no TypeScript errors.

---

## Reference

- `docs/dynamic-analysis-plan.md` — the design, including the Phase 6 UI notes
  this brief expands on.
- `docs/dynamic-analysis-notes.md` — what the backend implementation ran into,
  and its known gaps. Read the gaps: Android byte counts are not captured, so
  `bytes_sent` is frequently `null` and must render as absent, not as zero.
