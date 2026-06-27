import { createWorkersExporter } from "@mnemom/aip-otel-exporter/workers";
import { parseNdjson, transformToLoki, type LokiPushPayload } from "./transform";

interface Env {
  LOGPUSH_SECRET: string;
  LOKI_WRITE_URL: string;
  LOKI_TENANT_ID: string;
  LOKI_WRITE_TOKEN: string;
  // Ops coverage (issue #743) — OTLP span export. ARMED-DORMANT: createOTelExporter
  // returns null until OTLP_ENDPOINT is bound, so the relay emits no spans (and
  // adds no extra fetch) until the deploy repo wires the Grafana Cloud receiver.
  OTLP_ENDPOINT?: string;
  OTLP_AUTH?: string;
  // Deployment env stamped on the OTLP resource (mirrors gateway). Unset ⇒ the
  // exporter omits the label rather than guessing "production".
  ENVIRONMENT?: string;
  // MNE-892 cell tag. Blank/whitespace falls back to "us-1" via resolveCellId.
  CELL_ID?: string;
}

/**
 * Structural subset of the exporter we depend on. `recordSpan` lands a one-shot
 * span the metrics-generator folds into `traces_spanmetrics_*`. Feature-checked
 * at runtime (mirrors gateway/src/index.ts) so a pre-0.8 exporter degrades to a
 * no-op rather than throwing on the fire-and-forget telemetry path.
 */
interface RecordSpanCapable {
  recordSpan(input: {
    name: string;
    attributes?: Record<string, unknown>;
    status?: "ok" | "error" | "unset";
    durationMs?: number;
  }): void;
}

type OtelExporter = ReturnType<typeof createWorkersExporter> | null;
type SpanInput = Parameters<RecordSpanCapable["recordSpan"]>[0];

interface OwnershipChallenge {
  content: string;
  filename: string;
}

function tryParseOwnershipChallenge(text: string): string | null {
  try {
    const parsed: unknown = JSON.parse(text.trim());
    if (typeof parsed !== "object" || parsed === null) return null;
    if (!("filename" in parsed) || !("content" in parsed)) return null;
    const challenge = parsed as OwnershipChallenge;
    if (
      typeof challenge.filename === "string" &&
      challenge.filename.startsWith("ownership-challenge") &&
      typeof challenge.content === "string"
    ) {
      return challenge.content;
    }
  } catch {
    // not JSON — normal for NDJSON payloads
  }
  return null;
}

async function decompressGzip(buffer: ArrayBuffer): Promise<string> {
  const inputStream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array(buffer));
      controller.close();
    },
  });
  const decompressed = inputStream.pipeThrough(new DecompressionStream("gzip"));
  const reader = decompressed.getReader();
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0);
  const merged = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(merged);
}

/**
 * Result of a Loki push. `lokiStatus` is the HTTP status code of the final
 * attempt (issue #743) — surfaced so the `log_relay.push` / `log_relay.push_failure`
 * spans carry the real status code for Loki-side triage, not just success/failure.
 * `0` means the request never produced a response (network throw).
 */
interface LokiPushResult {
  ok: boolean;
  lokiStatus: number;
}

async function pushToLoki(payload: LokiPushPayload, env: Env): Promise<LokiPushResult> {
  const url = `${env.LOKI_WRITE_URL}/loki/api/v1/push`;
  const credentials = btoa(`${env.LOKI_TENANT_ID}:${env.LOKI_WRITE_TOKEN}`);
  const body = JSON.stringify(payload);

  for (let attempt = 1; attempt <= 2; attempt++) {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${credentials}`,
      },
      body,
    });
    if (res.ok) return { ok: true, lokiStatus: res.status };
    if (attempt < 2 && res.status >= 500) continue;
    console.error(`log-relay: Loki push failed with status ${res.status} (attempt ${attempt})`);
    return { ok: false, lokiStatus: res.status };
  }
  return { ok: false, lokiStatus: 0 };
}

// ============================================================================
// OTel ops coverage (issue #743)
//
// log-relay is the Logpush→Loki pipeline; before this it had no SLI. Three
// one-shot spans, folded into traces_spanmetrics_* by the metrics-generator,
// give the dashboard + alerts in dashboards/:
//
//   log_relay.push          Emitted on EVERY Loki push (success or failure).
//                           durationMs = push latency (→ latency histogram /
//                           "push latency" panel). attrs: loki_status, lines_in,
//                           outcome. status=ok|error.
//   log_relay.push_failure  ADR-043 counter-style breach span — emitted ONLY
//                           when a push fails both attempts. Powers the
//                           LokiPushFailureRateHigh alert (rate(...)>0). attrs:
//                           loki_status, lines_in. status=error.
//   log_relay.lines_dropped ADR-043 counter-style breach span — emitted ONLY
//                           when a batch had ≥1 unparseable NDJSON line, BEFORE
//                           the all-unparseable early-return so that drop case
//                           is captured. Powers LogLinesDroppedSpike. attrs:
//                           dropped_lines, lines_in. status=error.
//
// Separate span names (not one span with an outcome dimension) avoid the
// unpromoted-dimension NoData trap: spanmetrics only promotes configured
// dimensions, so a per-outcome rate must key off span_name. Per CLAUDE.md this
// Worker emits spans only — never OTLP metrics.
// ============================================================================

// MNE-892: the logical cell this Worker serves. Fixed low-cardinality enum
// (`us-1`) today; a blank/whitespace CELL_ID falls back so a hollow var never
// yields an empty cell_id. Mirrors gateway/observer resolveCellId.
function resolveCellId(env: Env): string {
  return env.CELL_ID?.trim() || "us-1";
}

function createOTelExporter(env: Env): OtelExporter {
  if (!env.OTLP_ENDPOINT) return null;
  return createWorkersExporter({
    endpoint: env.OTLP_ENDPOINT,
    authorization: env.OTLP_AUTH,
    serviceName: "mnemom-log-relay",
    // Stamp deployment env + cell on the OTLP resource so every span carries
    // them. Unset ENVIRONMENT ⇒ exporter omits the label (never a false
    // "production"). cell_id is a low-cardinality enum, not an OTLP metric.
    env: env.ENVIRONMENT,
    cell_id: resolveCellId(env),
  });
}

function recordSpanSafely(exporter: OtelExporter, input: SpanInput): void {
  if (!exporter) return;
  const ex = exporter as unknown as Partial<RecordSpanCapable>;
  if (typeof ex.recordSpan !== "function") return;
  try {
    ex.recordSpan(input);
  } catch {
    // Telemetry-only — fire-and-forget, never block the ingest path.
  }
}

function emitPushSpan(
  exporter: OtelExporter,
  ok: boolean,
  lokiStatus: number,
  linesIn: number,
  durationMs: number,
): void {
  recordSpanSafely(exporter, {
    name: "log_relay.push",
    attributes: {
      loki_status: lokiStatus,
      lines_in: linesIn,
      outcome: ok ? "success" : "failure",
    },
    status: ok ? "ok" : "error",
    durationMs,
  });
}

function emitPushFailureSpan(exporter: OtelExporter, lokiStatus: number, linesIn: number): void {
  recordSpanSafely(exporter, {
    name: "log_relay.push_failure",
    attributes: {
      loki_status: lokiStatus,
      lines_in: linesIn,
    },
    status: "error",
  });
}

function emitLinesDroppedSpan(exporter: OtelExporter, droppedLines: number, linesIn: number): void {
  recordSpanSafely(exporter, {
    name: "log_relay.lines_dropped",
    attributes: {
      dropped_lines: droppedLines,
      lines_in: linesIn,
    },
    status: "error",
  });
}

export default {
  async fetch(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const url = new URL(request.url);
    if (url.pathname !== "/logpush/workers-trace") {
      return new Response("Not Found", { status: 404 });
    }

    const secret = request.headers.get("X-Log-Relay-Secret");
    if (!env.LOGPUSH_SECRET || secret !== env.LOGPUSH_SECRET) {
      return new Response("Unauthorized", { status: 401 });
    }

    const buffer = await request.arrayBuffer();
    const encoding = request.headers.get("content-encoding") ?? "";
    const rawText = encoding.includes("gzip")
      ? await decompressGzip(buffer)
      : new TextDecoder().decode(buffer);

    const challengeToken = tryParseOwnershipChallenge(rawText);
    if (challengeToken !== null) {
      return new Response(challengeToken, {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    }

    // ARMED-DORMANT until OTLP_ENDPOINT is bound (createOTelExporter → null).
    const exporter = createOTelExporter(env);
    // Flush buffered spans before EVERY span-emitting return on the ingest path
    // (issue #743 advisory): the all-unparseable batch emits log_relay.lines_dropped
    // and then early-returns, so a push-only flush would lose that span before the
    // Worker instance dies. Fire-and-forget via waitUntil when ctx is present.
    const flush = (): void => {
      if (!exporter) return;
      try {
        const pending = Promise.resolve(exporter.flush()).catch(() => {
          // Export failure is telemetry-only — never surface on the ingest path.
        });
        if (ctx) ctx.waitUntil(pending);
      } catch {
        // A synchronous throw from flush() must not break log ingestion.
      }
    };

    const { records, skipped } = parseNdjson(rawText);
    // Total raw NDJSON lines Cloudflare sent (parsed + dropped) — additive with
    // dropped_lines so the dashboard's lines-in / lines-dropped panels reconcile.
    const linesIn = records.length + skipped;
    if (skipped > 0) {
      emitLinesDroppedSpan(exporter, skipped, linesIn);
    }

    if (records.length === 0) {
      flush();
      return new Response("OK", { status: 200 });
    }

    const payload = transformToLoki(records);
    if (payload.streams.length === 0) {
      flush();
      return new Response("OK", { status: 200 });
    }

    const startedAt = Date.now();
    const { ok, lokiStatus } = await pushToLoki(payload, env);
    emitPushSpan(exporter, ok, lokiStatus, linesIn, Date.now() - startedAt);
    if (!ok) {
      emitPushFailureSpan(exporter, lokiStatus, linesIn);
    }
    flush();
    return ok ? new Response("OK", { status: 200 }) : new Response("Bad Gateway", { status: 502 });
  },
};
