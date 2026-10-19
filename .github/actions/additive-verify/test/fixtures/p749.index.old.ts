import { parseNdjson, transformToLoki, type LokiPushPayload } from "./transform";

interface Env {
  LOGPUSH_SECRET: string;
  LOKI_WRITE_URL: string;
  LOKI_TENANT_ID: string;
  LOKI_WRITE_TOKEN: string;
  /** Deployment environment label ("production" | "staging"). Set in wrangler.toml [env.*.vars]. */
  ENVIRONMENT?: string;
}

/** Structural subset of an OTel exporter that supports recordSpan. No-op when null. */
interface RecordSpanCapable {
  recordSpan(input: {
    name: string;
    attributes?: Record<string, unknown>;
    status?: "ok" | "error" | "unset";
  }): void;
}

/**
 * Emits a log_relay.ndjson_dropped span when lines were silently skipped.
 * No-op when no exporter is configured — log-relay has no OTLP binding by default.
 * Alert stub: alert on sustained log_relay.ndjson_dropped (dropped > 0) over a 5-minute window.
 */
function emitNdjsonDroppedSpan(
  exporter: RecordSpanCapable | null,
  environment: string,
  dropped: number,
): void {
  if (!exporter) return;
  try {
    exporter.recordSpan({
      name: "log_relay.ndjson_dropped",
      attributes: { env: environment, dropped },
      // A dropped line is a soft data-loss event, not a failed emission — keep
      // status ok (matching the gateway/observer sibling spans) so it never
      // colors trace-level error rates. The alert keys off the `dropped`
      // attribute, not span status.
      status: "ok",
    });
  } catch {
    // Telemetry-only — fire-and-forget by design.
  }
}

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

async function pushToLoki(payload: LokiPushPayload, env: Env): Promise<boolean> {
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
    if (res.ok) return true;
    if (attempt < 2 && res.status >= 500) continue;
    console.error(`log-relay: Loki push failed with status ${res.status} (attempt ${attempt})`);
    return false;
  }
  return false;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
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

    const { records, skipped } = parseNdjson(rawText);
    if (skipped > 0) {
      emitNdjsonDroppedSpan(null, env.ENVIRONMENT ?? "unknown", skipped);
    }
    if (records.length === 0) {
      return new Response("OK", { status: 200 });
    }

    const payload = transformToLoki(records);
    if (payload.streams.length === 0) {
      return new Response("OK", { status: 200 });
    }

    const ok = await pushToLoki(payload, env);
    return ok ? new Response("OK", { status: 200 }) : new Response("Bad Gateway", { status: 502 });
  },
};
