import type {
  Health,
  Report,
  SampleSummary,
  UploadReceipt,
} from "./types";

/* Requests go to the same origin and are proxied to the backend in development
 * (see vite.config.ts), so no origin is baked into the bundle. */
const BASE = "/api";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, init);
  } catch {
    throw new ApiError("Can't reach the analysis service.", 0);
  }

  if (!response.ok) {
    throw new ApiError(await readError(response), response.status);
  }
  return (await response.json()) as T;
}

/* FastAPI reports failures as {detail}, which is already written for a reader.
 * Anything else falls back to a plain description of what happened. */
async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    const detail = (body as { detail?: unknown }).detail;
    if (typeof detail === "string" && detail) return detail;
  } catch {
    /* not JSON — fall through */
  }
  if (response.status === 404) return "That sample no longer exists.";
  if (response.status === 413) return "That file is too large to accept.";
  return `The analysis service returned ${response.status}.`;
}

export const api = {
  health: () => request<Health>("/health"),

  list: () => request<SampleSummary[]>("/samples"),

  get: (id: number) => request<Report>(`/samples/${id}`),

  upload(file: File, signal?: AbortSignal) {
    const form = new FormData();
    form.append("file", file);
    return request<UploadReceipt>("/samples", {
      method: "POST",
      body: form,
      signal,
    });
  },

  exportUrl: (id: number, format: "csv" | "stix") =>
    `${BASE}/samples/${id}/export.${format}`,

  /* The Word report is drafted on first download and can take a while, so it is
   * fetched rather than linked — a plain <a download> gives no way to show that
   * anything is happening. */
  async downloadWord(id: number): Promise<{ narrative: string }> {
    const response = await fetch(`${BASE}/samples/${id}/export.docx`);
    if (!response.ok) {
      throw new ApiError(await readError(response), response.status);
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filenameFrom(response) ?? `report-${id}.docx`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);

    return { narrative: response.headers.get("X-Narrative-Status") ?? "unknown" };
  },
};

function filenameFrom(response: Response): string | null {
  const disposition = response.headers.get("Content-Disposition");
  return disposition?.match(/filename="([^"]+)"/)?.[1] ?? null;
}
