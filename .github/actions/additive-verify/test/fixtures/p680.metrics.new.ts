/**
 * Observer queue observability — Step 52, span-derived per ADR-032 + ADR-033.
 *
 * Emits OTLP spans to $OTLP_ENDPOINT/v1/traces (the supported CF Workers path
 * per Grafana Cloud support ticket #225229). Grafana's metrics-generator
 * aggregates the spans into `traces_spanmetrics_*` series for RED-style
 * alerting; gauge-style queries use Tempo TraceQL metrics at query time.
 *
 * Three span families:
 *
 *   observer.queue_batch     One span per MessageBatch. Integer counts are
 *                            span attributes; carries `oldest_message_lag_ms`
 *                            measured from CF Queue message.timestamp at the
 *                            moment the consumer received the batch (ADR-033
 *                            — consumer-side lag, not from CF Analytics).
 *                            Dimensions: env, mode, gateway_id. Status=error
 *                            when stats.poison_acks > 0.
 *
 *   observer.queue_poison    One span per poison-acked message (emitted
 *                            stats.poison_acks times per batch). Makes
 *                            ObserverPoisonAckRate a direct spanmetrics
 *                            call-rate alert. Dimensions: env, mode,
 *                            gateway_id, reason=poison.
 *
 *   observer.queue_backlog   One span per queue per scheduled() tick,
 *                            carrying `depth` (avg messages backlogged) as
 *                            a numeric attribute. Depth alerts evaluate via
 *                            TraceQL max_over_time(span.depth). Dimensions:
 *                            env, queue, gateway_id.
 *
 * Source for backlog depth: CF GraphQL Analytics
 * `queueBacklogAdaptiveGroups.avg.messages`. Source for consumer lag:
 * `Date.now() - message.timestamp.getTime()` inside handleQueueBatch.
 * The split is deliberate — CF is the only signal source for backlog (we
 * can't see un-consumed messages); we are the only correct source for lag
 * (we know exactly when our consumer first saw a given message).
 *
 * Fire-and-forget posture preserved: unreachable backend is swallowed, the
 * batch has already been acked before emission. See ADR-032 for the pattern
 * choice + migration triggers toward a collector tier (Option B). See
 * ADR-033 for the consumer-side lag rationale.
 */

import type { BatchStats } from "./queue-consumer";
import { cfFetch, type CfApiGuardEnv } from "./cf-api-guard";

// Extends CfApiGuardEnv so the (optional) CF_API_* guard overrides ride along
// when MetricsEnv is handed to cfFetch — the worker Env supplies them at runtime.
export interface MetricsEnv extends CfApiGuardEnv {
  OTLP_ENDPOINT?: string;
  OTLP_AUTH?: string;
  GATEWAY_ID: string;
  OBSERVER_PROCESSING_MODE?: string;
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  /**
   * Shared KV namespace (the observer's BILLING_CACHE binding). Used here only
   * to persist the previous gateway-backlog sample so net drain rate can be
   * computed across cron ticks. Optional + fail-open: absence simply omits the
   * drain-rate gauge and the stalled-drain alert. Namespaced under
   * `observer:gw-backlog:*` so it can't collide with the LSH-index keys.
   */
  BILLING_CACHE?: KVNamespace;
  /**
   * Cell Architecture Phase 1 (C2 / MNE-892): the logical cell this Worker
   * serves. Optional; stamped on the per-log `observer.process_log` span's OTLP
   * resource via resolveCellId (defaults to "us-1"). Mirrors the Env field of
   * the same name in index.ts.
   */
  CELL_ID?: string;
}

export interface QueueDepth {
  queue: "main" | "dlq";
  /** Average backlog depth (messages) over the sample window. Source: CF
   *  GraphQL `queueBacklogAdaptiveGroups.avg.messages`. */
  messages: number;
}

/**
 * Snapshot of the CF AI Gateway log store — the producer's input and the
 * consumer's delete target (ADR-064 W5). Distinct from QueueDepth, which
 * measures un-consumed CF Queue messages. Either field is null when CF didn't
 * report a usable value that tick.
 */
export interface GatewayLogStats {
  /** Total gateway logs awaiting drain. Source: CF `/logs` result_info.total_count. */
  backlogDepth: number | null;
  /** Age of the oldest gateway log in ms (now − oldest.created_at). null if empty/unparseable. */
  oldestLogAgeMs: number | null;
  /**
   * Net logs drained per minute since the previous tick
   * ((prevDepth − curDepth) / elapsedMin). Positive = shrinking; ≤ 0 =
   * stalled or growing. null on the first sample or when KV is unavailable.
   */
  netDrainPerMin: number | null;
}

// ============================================================================
// Threshold-breach thresholds (ADR-043)
// ============================================================================
// Tempo TraceQL metrics aren't accepted as alert input by Grafana SSE (long-
// vs-wide data-frame mismatch). To make these gauges alertable via the same
// spanmetrics counter pattern that ObserverPoisonAckRate already uses, we
// emit a separate breach span only when a threshold is crossed. Alert rules
// then become PromQL `rate(traces_spanmetrics_calls_total{span_name=…})>0`.
// See ADR-043 for the full rationale and the alternatives considered.
export const QUEUE_BACKLOG_BREACH = 50_000; // main-queue depth; ~70 min backlog at Phase 1 target throughput.
export const QUEUE_DLQ_BREACH = 0; // any DLQ message is operationally interesting.
export const QUEUE_CONSUMER_LAG_BREACH_MS = 600_000; // 10 minutes — Step 53 SLO line.

// ---------------------------------------------------------------------------
// Gateway-backlog thresholds (ADR-064 W5)
// ---------------------------------------------------------------------------
// These guard the *gateway* log store (the ~139k-and-growing CF AI Gateway
// logs the producer polls and the consumer deletes) — distinct from the CF
// Queue backlog above. The two failure modes the 2026-05-28 storm proved we
// could not see:
//   (1) unbounded backlog GROWTH  → GATEWAY_BACKLOG_BREACH on total log count.
//   (2) a STALLED drain           → net drain ≤ 0 while a real backlog remains
//                                    (GATEWAY_STALL_MIN_DEPTH gate). Computed
//                                    from the cross-tick depth delta so it does
//                                    NOT false-page on a large-but-shrinking
//                                    backlog (the known historical tail that
//                                    W2/W3 will drain). Oldest-log age is
//                                    emitted as a gauge for dashboards but is
//                                    intentionally NOT a pager for that reason.
export const GATEWAY_BACKLOG_BREACH = 200_000; // total gateway logs; set above the known ~139k historical tail so a breach means growth *beyond* it (net arrivals outrunning drain = runaway), not the standing backlog W2/W3 will clear.
export const GATEWAY_STALL_MIN_DEPTH = 1_000; // don't cry "stalled" until there's a real backlog to drain.

// ============================================================================
// Ingestion-lag SLO + sampling (issue #538)
// ============================================================================
// Request → trace-in-DB latency: the time from a gateway log's `created_at` to
// the moment its trace lands in Supabase (a successful processLog). The SLO is
// p95 ≤ 5 min; positioned just above the "a few minutes" observed steady state
// like QUEUE_CONSUMER_LAG_BREACH_MS, so a breach means "worse than normal".
//
// The alert rides the same ADR-043 breach-span pattern as the gauges above: a
// counter-style observer.ingestion_lag_breach span fires only on threshold
// crossing, so the rule is PromQL rate(...calls_total)>0 — SSE-safe, unlike
// histogram_quantile() on Tempo TraceQL (which Grafana SSE cannot consume).
// Single constant so it is easy to retune.
export const INGESTION_LAG_SLO_BREACH_MS = 300_000; // 5 minutes — p95 ingestion-lag SLO.

// Per-batch cap on emitted observer.ingestion_lag duration spans. One span per
// processed log would ~double OTLP span volume on the firehose path (a real
// cost — MNE-440); even-stride sampling across the sorted lag distribution
// preserves shape (including the tail) at bounded volume. The panel reads
// percentiles/shape, not absolute throughput, so the scaled-down bucket counts
// are acceptable and documented in dashboards/README.md.
export const INGESTION_LAG_SAMPLE_MAX = 20;

/**
 * Nearest-rank percentile over a pre-sorted ascending numeric array. Returns 0
 * for empty input. The single shared implementation used by the queue consumer
 * and both cron paths to summarise ingestion-lag samples (issue #538) — kept
 * here so the three call sites can't diverge into separate logic-bearing copies.
 */
export function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(idx, sorted.length - 1))];
}

/**
 * Even-stride down-sample of a sorted ascending array to at most `cap` entries,
 * always retaining the first and last element so the distribution tail (max) is
 * represented in the emitted histogram. Returns a copy; never mutates input.
 */
function strideSample(sorted: number[], cap: number): number[] {
  if (cap <= 0) return [];
  if (sorted.length <= cap) return sorted.slice();
  if (cap === 1) return [sorted[sorted.length - 1]];
  const out: number[] = [];
  const step = (sorted.length - 1) / (cap - 1);
  for (let i = 0; i < cap; i++) out.push(sorted[Math.round(i * step)]);
  return out;
}

/**
 * Apply the same even-stride index selection used by strideSample to a parallel
 * array of mnemom_request_ids, preserving the lag↔requestId alignment through
 * the down-sample (MNE-1066). `reference` must already be sorted ascending and
 * have the same length as `parallel`.
 */
function strideSampleParallel(
  reference: number[],
  parallel: Array<string | undefined>,
  cap: number,
): Array<string | undefined> {
  if (cap <= 0) return [];
  if (reference.length <= cap) return parallel.slice();
  if (cap === 1) return [parallel[parallel.length - 1]];
  const out: Array<string | undefined> = [];
  const step = (reference.length - 1) / (cap - 1);
  for (let i = 0; i < cap; i++) out.push(parallel[Math.round(i * step)]);
  return out;
}

/**
 * Aggregated ingestion-lag statistics for a batch/tick (issue #538). Units are
 * milliseconds except `ingestion_lag_count` (unitless sample size). `samples` is
 * the even-stride-capped (≤ INGESTION_LAG_SAMPLE_MAX) sorted lag set retained
 * for histogram-span emission; the count/sum/percentiles are computed over the
 * FULL sample set, not the capped slice.
 */
export interface IngestionLagSummary {
  ingestion_lag_count: number;
  ingestion_lag_sum_ms: number;
  ingestion_lag_p50_ms: number;
  ingestion_lag_p95_ms: number;
  ingestion_lag_max_ms: number;
  ingestion_lag_samples: number[];
  /**
   * Per-sample mnemom_request_ids aligned with ingestion_lag_samples (MNE-1066).
   * Absent when the caller did not supply request IDs (e.g. cron tick without
   * mnemom_request_id). When present, used by buildIngestionLagSpan to derive a
   * W3C-correlatable traceId via deriveOtlpTraceId so gateway and observer spans
   * share a trace id in Tempo.
   */
  ingestion_lag_request_ids?: Array<string | undefined>;
}

/**
 * Summarise raw per-log ingestion-lag samples (ms) into histogram-style stats.
 * Empty input → all-zero summary with no samples (the cold-start / no-parseable-
 * created_at case: no spans, no breach). Shared by handleQueueBatch and the two
 * cron paths so the aggregation logic lives in exactly one tested place
 * (MNE-437 — no divergent duplicates).
 *
 * MNE-1066: optional rawRequestIds, when provided, is sorted alongside
 * rawSamples (maintaining lag↔requestId alignment) and stride-sampled in
 * parallel. The result carries ingestion_lag_request_ids so the span emitter
 * can derive per-span W3C trace ids from mnemom_request_id.
 */
export function summariseIngestionLag(
  rawSamples: number[],
  rawRequestIds?: Array<string | undefined>,
): IngestionLagSummary {
  const count = rawSamples.length;
  if (count === 0) {
    return {
      ingestion_lag_count: 0,
      ingestion_lag_sum_ms: 0,
      ingestion_lag_p50_ms: 0,
      ingestion_lag_p95_ms: 0,
      ingestion_lag_max_ms: 0,
      ingestion_lag_samples: [],
    };
  }
  // Sort by lagMs, maintaining alignment with rawRequestIds when provided.
  let sorted: number[];
  let sortedIds: Array<string | undefined> | undefined;
  if (rawRequestIds) {
    const pairs = rawSamples.map((lagMs, i) => ({ lagMs, requestId: rawRequestIds[i] }));
    pairs.sort((a, b) => a.lagMs - b.lagMs);
    sorted = pairs.map((p) => p.lagMs);
    sortedIds = pairs.map((p) => p.requestId);
  } else {
    sorted = [...rawSamples].sort((a, b) => a - b);
  }
  let sum = 0;
  for (const v of sorted) sum += v;
  const cappedSamples = strideSample(sorted, INGESTION_LAG_SAMPLE_MAX);
  const cappedIds = sortedIds
    ? strideSampleParallel(sorted, sortedIds, INGESTION_LAG_SAMPLE_MAX)
    : undefined;
  return {
    ingestion_lag_count: count,
    ingestion_lag_sum_ms: sum,
    ingestion_lag_p50_ms: percentile(sorted, 50),
    ingestion_lag_p95_ms: percentile(sorted, 95),
    ingestion_lag_max_ms: sorted[count - 1],
    ingestion_lag_samples: cappedSamples,
    ...(cappedIds !== undefined ? { ingestion_lag_request_ids: cappedIds } : {}),
  };
}

// ============================================================================
// W3C-correlatable trace id derivation (MNE-1066)
// ============================================================================

/**
 * Derive a W3C-format OTLP traceId from a mnemom_request_id. Returns the first
 * 32 hex chars of SHA-256(requestId) — 128 bits, the W3C trace-id width —
 * deterministic and collision-resistant, so gateway and observer spans for the
 * same request share a trace id in Tempo. Mirrors deriveTraceId (log.id →
 * trace_id) with a wider 32-char output to match the OTLP traceId field.
 */
export async function deriveOtlpTraceId(requestId: string): Promise<string> {
  const bytes = new TextEncoder().encode(requestId);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 32);
}

// ============================================================================
// Span emitters
// ============================================================================

/**
 * Emit the per-batch `observer.queue_batch` span plus one `observer.queue_poison`
 * span for each poison-acked message in the batch. Safe to call with a
 * zero-message batch.
 */
export async function emitQueueBatchSpan(env: MetricsEnv, stats: BatchStats): Promise<void> {
  if (!env.OTLP_ENDPOINT) return;

  const mode = env.OBSERVER_PROCESSING_MODE ?? "direct";
  const env_ = envLabel(env);
  const gw = env.GATEWAY_ID;

  const spans: OtlpSpan[] = [buildBatchSpan(env_, mode, gw, stats)];
  for (let i = 0; i < stats.poison_acks; i++) {
    spans.push(buildPoisonSpan(env_, mode, gw));
  }
  // ADR-065 #13 — one orphan span per fast-failed missing-agent-FK trace. A
  // distinct span name (not folded into queue_poison) so the orphaned-agent
  // drain rate is alertable separately from genuine poison — orphans are an
  // expected, fleet-provisioning-driven condition (#17), not malformed input.
  for (let i = 0; i < stats.orphan_acks; i++) {
    spans.push(buildOrphanSpan(env_, mode, gw));
  }
  // ADR-043 — emit a counter-style breach span when consumer lag crosses
  // the SLO threshold so the alert layer can fire on rate(...)>0.
  //
  // Gate also requires (processed > 0 || retries > 0) — the alert is
  // intended to detect "consumer can't keep up with real load", which
  // requires the consumer to actually be doing work (or retrying it).
  // Skipped-only batches are by-design idempotency churn from the
  // producer's intentional re-enqueue pattern (queue-producer.ts §"R2
  // path: ... duplicate enqueueing across ticks is absorbed by Step 51's
  // submitTrace idempotency"). Counting those as lag breaches inflates
  // the alert with non-actionable noise — observed 2026-05-04: every
  // high-lag batch in the firing window had `processed=0, skipped=N,
  // retries=0`, meaning the consumer was idle-skipping at I/O speed
  // while the producer fed it stale records. See triage doc
  // observer-alert-triage-2026-05-04.md §3.7.
  const didRealWork = stats.processed > 0 || stats.retries > 0;
  if (stats.oldest_message_lag_ms > QUEUE_CONSUMER_LAG_BREACH_MS && didRealWork) {
    spans.push(buildLagBreachSpan(env_, mode, gw, stats.oldest_message_lag_ms));
  }

  // MNE-1138 — ADR-043 counter-style breach spans for message disposition
  // buckets. Fires only when the batch had non-zero retries/acks in that
  // bucket; no-ops on a clean batch. rate(...)>0 alerts on the first dirty batch.
  if (stats.backpressure_retries > 0) {
    spans.push(
      buildMessageDispositionBreachSpan(env_, mode, gw, "backpressure", stats.backpressure_retries),
    );
  }
  if (stats.orphan_acks > 0) {
    spans.push(buildMessageDispositionBreachSpan(env_, mode, gw, "orphan", stats.orphan_acks));
  }
  if (stats.poison_acks > 0) {
    spans.push(buildMessageDispositionBreachSpan(env_, mode, gw, "poison", stats.poison_acks));
  }

  // Issue #538 — duration-encoded ingestion-lag histogram spans (bounded by
  // INGESTION_LAG_SAMPLE_MAX via the capped stats.ingestion_lag_samples) plus
  // the ADR-043 SLO breach span. Empty samples / count===0 ⇒ nothing added.
  // MNE-1066: pass ingestion_lag_request_ids so each span gets a traceId derived
  // from mnemom_request_id rather than a fresh random one.
  spans.push(
    ...(await buildIngestionLagSpans(
      env_,
      mode,
      gw,
      stats.ingestion_lag_samples,
      stats.ingestion_lag_p95_ms,
      stats.ingestion_lag_count,
      stats.ingestion_lag_request_ids,
    )),
  );

  await postSpans(env, spans);
}

/**
 * Issue #538 — emit the cron-path ingestion-lag histogram + breach spans. The
 * queue path folds these into emitQueueBatchSpan; the cron tick has no batch
 * span to ride, so emitTickSummary calls this fire-and-forget after building the
 * observer.cron_tick span. No-ops when OTLP is unset or there are no samples /
 * no breach, so a healthy empty tick posts nothing.
 *
 * MNE-1066: optional requestIds (aligned with samples) are threaded through to
 * buildIngestionLagSpans so each span gets a W3C-correlatable traceId derived
 * from mnemom_request_id rather than a fresh random one.
 */
export async function emitIngestionLagSpans(
  env: MetricsEnv,
  samples: number[],
  p95Ms: number,
  count: number,
  requestIds?: Array<string | undefined>,
): Promise<void> {
  if (!env.OTLP_ENDPOINT) return;
  const mode = env.OBSERVER_PROCESSING_MODE ?? "direct";
  const spans = await buildIngestionLagSpans(
    envLabel(env),
    mode,
    env.GATEWAY_ID,
    samples,
    p95Ms,
    count,
    requestIds,
  );
  if (spans.length === 0) return;
  await postSpans(env, spans);
}

/**
 * Emit queue-state backlog spans (one per queue) for the current tick.
 * Called from scheduled() after fetchQueueDepths resolves. A null or empty
 * depths arg is a no-op so the caller can chain
 * `fetchQueueDepths(env).then(d => d && emit(...))` unchanged.
 */
export async function emitQueueBacklogSpans(env: MetricsEnv, depths: QueueDepth[]): Promise<void> {
  if (!env.OTLP_ENDPOINT || depths.length === 0) return;

  const env_ = envLabel(env);
  const gw = env.GATEWAY_ID;

  const spans: OtlpSpan[] = depths.map((d) => buildBacklogSpan(env_, gw, d));
  // ADR-043 — counter-style breach spans for the depth gauges.
  for (const d of depths) {
    if (d.queue === "main" && d.messages > QUEUE_BACKLOG_BREACH) {
      spans.push(buildDepthBreachSpan("observer.queue_backlog_breach", env_, gw, d));
    } else if (d.queue === "dlq" && d.messages > QUEUE_DLQ_BREACH) {
      spans.push(buildDepthBreachSpan("observer.queue_dlq_breach", env_, gw, d));
    }
  }
  await postSpans(env, spans);
}

/**
 * ADR-064 W5 — fetch the gateway-log snapshot, compute net drain rate against
 * the previous tick (KV), and emit the gateway-backlog gauge + breach spans.
 * One orchestrator so scheduled() wires it in a single fire-and-forget line.
 *
 * Fully fail-open: a null fetch (CF error / unknown gateway) emits nothing;
 * KV being absent or throwing just omits the drain-rate gauge and the
 * stalled-drain breach. Never throws — mirrors the module's fire-and-forget
 * posture. nowMs is injectable for tests; defaults to wall-clock.
 */
export async function reportGatewayBacklog(
  env: MetricsEnv,
  nowMs: number = Date.now(),
): Promise<void> {
  if (!env.OTLP_ENDPOINT) return;
  const stats = await fetchGatewayLogStats(env, nowMs);
  if (!stats) return;
  if (stats.backlogDepth !== null) {
    stats.netDrainPerMin = await computeNetDrainPerMin(env, stats.backlogDepth, nowMs);
  }
  await emitGatewayBacklogSpans(env, stats);
}

/**
 * Emit the `observer.gateway_backlog` gauge span (depth + oldest-log age +
 * net drain rate) plus ADR-043 counter-style breach spans:
 *   - observer.gateway_backlog_breach     depth > GATEWAY_BACKLOG_BREACH
 *                                          (unbounded growth beyond the tail).
 *   - observer.gateway_drain_stalled_breach  net drain ≤ 0 while depth exceeds
 *                                          GATEWAY_STALL_MIN_DEPTH (drain
 *                                          stalled with a real backlog still
 *                                          queued — pages within minutes).
 *
 * `drain rate (deletes/min)` is exposed two ways: the `net_drain_per_min`
 * attribute on the gauge (KV cross-tick delta — net of new arrivals, the
 * "is the backlog shrinking?" signal) and, for query-time use, the negative
 * derivative of the depth gauge in Tempo, matching the queue_backlog
 * convention. The *alert* rides the stateless-ish breach spans, not a
 * derivative, since Grafana SSE can't take TraceQL as alert input (ADR-043).
 *
 * Exported (and separable from the fetch) so tests can drive span shape with
 * hand-built stats. A null-everywhere stats object still emits the gauge so a
 * total CF outage is itself visible as a gap, consistent with the other gauges.
 */
export async function emitGatewayBacklogSpans(
  env: MetricsEnv,
  stats: GatewayLogStats,
): Promise<void> {
  if (!env.OTLP_ENDPOINT) return;
  const env_ = envLabel(env);
  const gw = env.GATEWAY_ID;

  const spans: OtlpSpan[] = [buildGatewayBacklogSpan(env_, gw, stats)];

  if (stats.backlogDepth !== null && stats.backlogDepth > GATEWAY_BACKLOG_BREACH) {
    spans.push(buildGatewayBreachSpan("observer.gateway_backlog_breach", env_, gw, stats));
  }
  // Stalled drain: a real backlog remains AND it isn't shrinking. Requires a
  // prior sample (netDrainPerMin !== null) so we never page on the first tick.
  if (
    stats.backlogDepth !== null &&
    stats.backlogDepth > GATEWAY_STALL_MIN_DEPTH &&
    stats.netDrainPerMin !== null &&
    stats.netDrainPerMin <= 0
  ) {
    spans.push(buildGatewayBreachSpan("observer.gateway_drain_stalled_breach", env_, gw, stats));
  }

  await postSpans(env, spans);
}

/**
 * ADR-064 W8 / ADR-043 — emit a counter-style span when the CF management-API
 * circuit breaker trips (closed→open). A trip means the observer is being
 * throttled against Cloudflare's account-global, shared-with-deploys API
 * budget — the deploy-contention signal we want visible during the staging
 * soak that informs the conservative CF_API_MAX_CALLS_PER_WINDOW cap (started
 * at 18). status=ERROR rolls into the per-name `traces_spanmetrics_*` series
 * so the alert is the same PromQL `rate(...) > 0` shape as the other breach
 * spans. Registered as the cf-api-guard breaker-open listener from index.ts.
 *
 * Fire-and-forget (matches the module's posture); never throws.
 */
export function emitCircuitBreakerOpenSpan(
  env: MetricsEnv,
  label: string,
  failures: number,
  threshold: number,
): void {
  if (!env.OTLP_ENDPOINT) return;
  const span = buildCircuitOpenSpan(envLabel(env), env.GATEWAY_ID, label, failures, threshold);
  void postSpans(env, [span]);
}

/**
 * Issue #703 — fire-and-forget span when the LLM customer-path probe fails
 * (probeLLMReachability returns ok=false). The span name
 * `observer.llm_probe_failed` is a counter-style ADR-043 breach span:
 * spanmetrics rolls it into `traces_spanmetrics_calls_total`, and the alert
 * rule fires on rate(...)>0. `is_rate_limited` distinguishes a 429 stall
 * (Anthropic quota) from a generic network/5xx error. status=ERROR so the
 * span rolls into the per-name series, matching the circuit-breaker convention.
 *
 * Fire-and-forget (matches the module's posture); never throws.
 * NOTE: only called from within the `if (env.BETTERSTACK_LLM_HEARTBEAT_URL)`
 * block in index.ts scheduled(), so a deployment with OTLP but without that
 * env will never run the probe and never emit this span — see the Known
 * Limitations note in grafana-observer-llm-heartbeat-alerts.yaml.
 */
export function emitLLMProbeFailedSpan(env: MetricsEnv, isRateLimited: boolean): void {
  if (!env.OTLP_ENDPOINT) return;
  const span = buildLLMProbeFailedSpan(envLabel(env), env.GATEWAY_ID, isRateLimited);
  void postSpans(env, [span]);
}

/**
 * The four terminal outcomes submitTrace classifies (issue #660 / MNE-1056).
 * `written` and `pk_conflict` are successful (status OK); `orphan_fk` and
 * `transient_error` are failures (status ERROR).
 */
export type SubmitTraceOutcome = "written" | "pk_conflict" | "orphan_fk" | "transient_error";

/**
 * Per-tick stats carried on the `observer.cron_tick` span (issue #689).
 * Mirrors the fields of `ProcessingStats` in index.ts that appear as span
 * attributes — defined here so the builder lives in metrics.ts alongside all
 * other span builders.
 */
export interface CronTickStats {
  logs_fetched: number;
  processed: number;
  errors: number;
  logs_unidentified: number;
  first_error_name?: string;
  first_error_message?: string;
  ingestion_lag_p50_ms?: number;
  ingestion_lag_p95_ms?: number;
  ingestion_lag_max_ms?: number;
  ingestion_lag_sum_ms?: number;
  ingestion_lag_count?: number;
}

/**
 * Issue #660 / MNE-1056 — fire-and-forget `observer.submit_trace` span recording
 * the terminal DB-write outcome of submitTrace. Before this, each of the three
 * classified outcomes (PK conflict, orphan-agent FK, generic transient) only
 * emitted a console.log/throw, so neither the write latency nor the rate of
 * each outcome — especially `orphan_fk`, the documented push-DLQ poison root
 * cause — was alertable as a spanmetrics series. The span's DURATION encodes the
 * measured DB-write time so Grafana's metrics-generator derives a native
 * `traces_spanmetrics_duration_*` histogram; the same value also rides as a
 * `durationMs` attribute for TraceQL triage. status=ERROR for the two failing
 * outcomes (`orphan_fk`, `transient_error`) so they roll into the per-name
 * `traces_spanmetrics_calls_total` series, matching the breach-span convention.
 *
 * Fire-and-forget (matches the module's posture); never throws. `cellId` is
 * resolved by the caller and passed in: the postSpans path stamps only
 * service.name on the OTLP resource, so — unlike the @mnemom/aip-otel-exporter
 * path — it cannot carry a resource-level `cell_id`; we attach it per span.
 */
export function emitSubmitTraceSpan(
  env: MetricsEnv,
  outcome: SubmitTraceOutcome,
  durationMs: number,
  cellId: string,
): void {
  if (!env.OTLP_ENDPOINT) return;
  const span = buildSubmitTraceSpan(envLabel(env), cellId, outcome, durationMs);
  void postSpans(env, [span]);
}

/**
 * The three terminal outcomes of the customer-path LLM reachability probe
 * (issue #688). `ok` is a successful Anthropic call (status OK); `rate_limited`
 * (a 429) and `error` (any other failure) are failures (status ERROR).
 */
export type LLMProbeOutcome = "ok" | "rate_limited" | "error";

/**
 * Issue #688 — fire-and-forget `observer.llm_probe` span recording the outcome and
 * latency of probeLLMReachability's real customer-path Anthropic call. Before this,
 * the probe emitted a span on NEITHER success nor failure — only a console.warn
 * (observer_llm_probe_failed) on failure — so probe latency and the success/429
 * rate were invisible to spanmetrics, leaving the customer-path-reachability signal
 * a BetterStack heartbeat only with no Grafana-side latency/error trend. The span's
 * DURATION encodes the measured call wall-clock so Grafana's metrics-generator
 * derives a native `traces_spanmetrics_duration_*` histogram; the same value rides
 * as a `durationMs` attribute for triage. status=ERROR for a failed probe
 * (`rate_limited`, `error`) so it rolls into the per-name
 * `traces_spanmetrics_calls_total` series, matching the submit_trace / breach-span
 * convention.
 *
 * Fire-and-forget (matches the module's posture); never throws. The env param is
 * narrowed to only the fields the emitter reads — satisfied structurally by both the
 * full worker `Env` (production) and probeLLMReachability's partial probe env (tests)
 * — so the type stays compatible across both call sites (MNE-414 advisory).
 */
export function emitLLMProbeSpan(
  env: Pick<MetricsEnv, "OTLP_ENDPOINT" | "OTLP_AUTH"> & { GATEWAY_ID?: string },
  outcome: LLMProbeOutcome,
  durationMs: number,
): void {
  if (!env.OTLP_ENDPOINT) return;
  // OTLP_ENDPOINT confirmed non-null above. postSpans reads only OTLP_ENDPOINT /
  // OTLP_AUTH, and envLabel reads only GATEWAY_ID (→ "unknown" when absent); the
  // cast satisfies their existing MetricsEnv signatures without widening them
  // (MNE-414 advisory).
  const envForPost = env as MetricsEnv;
  const span = buildLLMProbeSpan(envLabel(envForPost), outcome, durationMs);
  void postSpans(envForPost, [span]);
}

/**
 * Issue #659 — emit a single duration-encoded observer.haiku_analysis span per
 * Haiku trace-analysis model call (callAnthropicMessages in analyzeWithHaiku).
 * The span's DURATION encodes the model-call latency so Grafana's
 * metrics-generator derives a native traces_spanmetrics_duration_seconds
 * histogram for compute-latency/health alerting; `analysis.outcome` (ok/error)
 * splits the success and failure series and `analysis.shadow` distinguishes the
 * primary analysis call from the shadow-chain call. Scope is the MODEL CALL
 * ONLY — JSON parse/validation failures that throw AFTER the call resolves are
 * still attributed analysis.outcome=ok, so this is a latency/health signal, not
 * an analysis-quality signal.
 *
 * Carries the GenAI semantic-convention attributes gen_ai.system=anthropic and
 * gen_ai.request.model so the series is attributable to the model behind it.
 *
 * Fire-and-forget + OTLP-gated, matching emitCircuitBreakerOpenSpan: a no-op
 * when OTLP_ENDPOINT is unset, and an unreachable backend is swallowed so the
 * analysis path never blocks on telemetry.
 */
export function emitHaikuAnalysisSpan(
  env: MetricsEnv,
  durationMs: number,
  outcome: "ok" | "error",
  model: string,
  shadow: boolean,
): void {
  if (!env.OTLP_ENDPOINT) return;
  const span = buildHaikuAnalysisSpan(
    envLabel(env),
    env.OBSERVER_PROCESSING_MODE ?? "direct",
    env.GATEWAY_ID,
    durationMs,
    outcome,
    model,
    shadow,
  );
  void postSpans(env, [span]);
}

// ---------------------------------------------------------------------------
// Per-log process_log span (issue #658)
// ---------------------------------------------------------------------------

/**
 * Issue #658 — map processLog's tri-state return onto the per-log span outcome
 * enum: `true → processed`, `null → unidentified`, `false → skipped`. A thrown
 * failure is classified as `error` at the emit site (emitProcessLogSpan input),
 * not here — so every branch of this pure mapper is reachable (MNE-437). Mirrors
 * the classify() fork in unidentified-retention.test.ts so the two never diverge.
 */
export function processLogOutcome(
  result: boolean | null,
): "processed" | "skipped" | "unidentified" {
  if (result === true) return "processed";
  if (result === null) return "unidentified";
  return "skipped";
}

/**
 * Inputs for one `observer.process_log` span. `outcome` is the resolved terminal
 * outcome (processLogOutcome for a return, or `"error"` for a throw); `errored`
 * drives span status (ERROR only on a thrown failure). `durationMs` is the full
 * processLog wall-clock measured inside the Worker (always ≥ 0 in practice —
 * both clocks are the same invocation; int() additionally clamps to ≥ 0).
 */
export interface ProcessLogSpanInput {
  source: "polling" | "r2" | "push";
  outcome: "processed" | "skipped" | "unidentified" | "error";
  provider: string;
  durationMs: number;
  errored: boolean;
}

/**
 * Issue #658 — emit exactly one per-log `observer.process_log` span carrying the
 * pipeline's terminal outcome + wall-clock duration. Fire-and-forget: no-ops
 * without an OTLP endpoint and swallows fetch errors (matches postSpans /
 * emitTickSummary posture, MNE-442 — telemetry failure never breaks ingestion).
 *
 * `cell_id` rides the OTLP *resource* (not a span attribute), matching the
 * WorkersOTelExporter resource-stamping convention (MNE-892) — hence the
 * dedicated envelope rather than reusing postSpans / buildOtlpSpansBody (which
 * put only `service.name` on the resource; left untouched so their existing
 * callers/tests are unaffected, MNE-437).
 *
 * Outcome vocabulary note (issue #658 / MNE-414): this per-log span emits
 * `processed | skipped | unidentified | error`. The issue's conceptual outcome
 * list also names `orphan` (missing-agent FK 23503) and `poison` (malformed
 * queue message), but in this codebase those are classified by the QUEUE
 * CONSUMER's catch block, not inside processLog — from processLog's perspective
 * both surface as a thrown error → `outcome=error` / `status=ERROR`. The
 * batch-level `observer.queue_orphan` / `observer.queue_poison` spans remain the
 * attribution path for those classes; adding unreachable orphan/poison branches
 * here would be logic-bearing dead code (MNE-437). A future `outcomeOverride`
 * threaded from the queue consumer is the scoped follow-up (see plan).
 */
export async function emitProcessLogSpan(env: MetricsEnv, in_: ProcessLogSpanInput): Promise<void> {
  if (!env.OTLP_ENDPOINT) return;
  const span = buildProcessLogSpan(envLabel(env), in_);
  // Dedicated envelope: service.name AND cell_id on the resource (issue #658).
  const body = JSON.stringify({
    resourceSpans: [
      {
        resource: {
          attributes: [
            { key: "service.name", value: { stringValue: "mnemom-observer" } },
            { key: "cell_id", value: { stringValue: resolveCellId(env) } },
          ],
        },
        scopeSpans: [{ scope: { name: "observer.process_log" }, spans: [span] }],
      },
    ],
  });
  try {
    await fetch(`${env.OTLP_ENDPOINT}/v1/traces`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(env.OTLP_AUTH ? { Authorization: env.OTLP_AUTH } : {}),
      },
      body,
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    // Swallowed — fire-and-forget matches postSpans' posture.
  }
}

// ============================================================================
// Span builders
// ============================================================================

interface OtlpAttributeValue {
  stringValue?: string;
  intValue?: string;
  boolValue?: boolean;
}
interface OtlpAttribute {
  key: string;
  value: OtlpAttributeValue;
}
interface OtlpSpanStatus {
  code: 0 | 1 | 2; // 0=UNSET, 1=OK, 2=ERROR
}
interface OtlpSpan {
  traceId: string;
  spanId: string;
  name: string;
  kind: 1; // INTERNAL
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: OtlpAttribute[];
  status: OtlpSpanStatus;
}

function buildBatchSpan(
  env_: string,
  mode: string,
  gatewayId: string,
  stats: BatchStats,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.queue_batch",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("mode", mode),
      str("gateway_id", gatewayId),
      int("batch_size", stats.total),
      int("processed", stats.processed),
      int("skipped", stats.skipped),
      // subset of skipped; cf-aig-metadata dropped signal (#687)
      int("logs_unidentified", stats.logs_unidentified),
      int("acks_on_missing", stats.acks_on_missing),
      int("poison_acks", stats.poison_acks),
      int("retries", stats.retries),
      // ADR-065 #13 — circuit-open backpressure deferrals (DB breaker tripped).
      int("backpressure_retries", stats.backpressure_retries),
      // ADR-065 #13 — orphaned-agent traces fast-failed (missing-agent FK 23503),
      // acked instead of dead-lettered. The direct push-DLQ-poison signal.
      int("orphan_acks", stats.orphan_acks),
      // Consumer-side lag (ADR-033) — TraceQL alerts on max_over_time(span.oldest_message_lag_ms).
      int("oldest_message_lag_ms", stats.oldest_message_lag_ms),
      // Issue #538 — request→trace-in-DB ingestion-lag summary for Tempo
      // trace-search TRIAGE ONLY (omitted when no log with a parseable
      // created_at landed this batch). The SLO *alert* rides the
      // observer.ingestion_lag_breach span and the *panel* rides the
      // observer.ingestion_lag spanmetrics duration histogram (ADR-043) — these
      // per-batch percentiles cannot be re-aggregated into a correct global one.
      ...(stats.ingestion_lag_count > 0
        ? [
            int("ingestion_lag_p50_ms", stats.ingestion_lag_p50_ms),
            int("ingestion_lag_p95_ms", stats.ingestion_lag_p95_ms),
            int("ingestion_lag_max_ms", stats.ingestion_lag_max_ms),
            int("ingestion_lag_sum_ms", stats.ingestion_lag_sum_ms),
            int("ingestion_lag_count", stats.ingestion_lag_count),
          ]
        : []),
    ],
    status: { code: stats.poison_acks > 0 ? 2 : 1 },
  };
}

/**
 * Issue #658 — build the per-log `observer.process_log` span. Point-in-time
 * (start == end, matching buildBatchSpan); the full processLog wall-clock rides
 * the `duration_ms` integer attribute (queryable via TraceQL
 * avg(span.duration_ms)). All attributes are low-cardinality enums or a numeric
 * duration — no per-log/agent/trace ids (CLAUDE.md: high-cardinality → logs).
 * `cell_id` is NOT an attribute here; it rides the OTLP resource (see
 * emitProcessLogSpan). status=ERROR only on a thrown failure.
 */
function buildProcessLogSpan(env_: string, in_: ProcessLogSpanInput): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.process_log",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("source", in_.source),
      str("outcome", in_.outcome),
      str("provider", in_.provider || "unknown"),
      str("env", env_),
      int("duration_ms", in_.durationMs),
    ],
    status: { code: in_.errored ? 2 : 1 },
  };
}

/**
 * Issue #538 — build the duration-encoded ingestion-lag histogram spans (one per
 * capped sample) plus the ADR-043 SLO breach span. Returns [] when there are no
 * samples and no breach. Shared by emitQueueBatchSpan and emitIngestionLagSpans.
 *
 * MNE-1066: async so each span's traceId can be derived from the corresponding
 * mnemom_request_id via deriveOtlpTraceId. Falls back to hex32() when the entry
 * in requestIds is absent.
 */
async function buildIngestionLagSpans(
  env_: string,
  mode: string,
  gatewayId: string,
  samples: number[],
  p95Ms: number,
  count: number,
  requestIds?: Array<string | undefined>,
): Promise<OtlpSpan[]> {
  const spans: OtlpSpan[] = [];
  for (let i = 0; i < samples.length; i++) {
    const requestId = requestIds?.[i];
    const traceId = requestId ? await deriveOtlpTraceId(requestId) : hex32();
    spans.push(buildIngestionLagSpan(env_, mode, gatewayId, samples[i], traceId));
  }
  // Fail-closed SLO breach: fires ONLY when real data is genuinely slow
  // (count > 0 && p95 > SLO). The no-traffic / cold-start case never pages here
  // — pipeline-dead detection is owned by the dual-heartbeat (#514) + queue
  // backlog/lag alerts (MNE-442). Documented in the alert YAML header.
  if (count > 0 && p95Ms > INGESTION_LAG_SLO_BREACH_MS) {
    spans.push(buildIngestionLagBreachSpan(env_, mode, gatewayId, p95Ms));
  }
  return spans;
}

/**
 * Issue #538 — a single observer.ingestion_lag span whose DURATION encodes the
 * request→trace-in-DB lag (start = created_at, end = now), so Grafana's
 * metrics-generator turns it into a native traces_spanmetrics_duration_seconds
 * histogram. Only low-cardinality dimensions (env/mode/gateway_id); status=OK.
 *
 * MNE-1066: traceId is pre-computed by the caller (derived from mnemom_request_id
 * via deriveOtlpTraceId, or hex32() when the request id is absent).
 */
function buildIngestionLagSpan(
  env_: string,
  mode: string,
  gatewayId: string,
  lagMs: number,
  traceId: string,
): OtlpSpan {
  const endMs = Date.now();
  const startMs = endMs - Math.max(0, lagMs);
  return {
    traceId,
    spanId: hex16(),
    name: "observer.ingestion_lag",
    kind: 1,
    startTimeUnixNano: String(startMs * 1_000_000),
    endTimeUnixNano: String(endMs * 1_000_000),
    attributes: [str("env", env_), str("mode", mode), str("gateway_id", gatewayId)],
    status: { code: 1 },
  };
}

/**
 * Issue #538 / ADR-043 — counter-style breach span emitted only when a batch's
 * p95 ingestion lag exceeds INGESTION_LAG_SLO_BREACH_MS. Carries the breached
 * p95 for triage; the alert fires on rate(...calls_total)>0. status=ERROR so it
 * rolls into the per-name traces_spanmetrics_* series, mirroring buildLagBreachSpan.
 */
function buildIngestionLagBreachSpan(
  env_: string,
  mode: string,
  gatewayId: string,
  p95Ms: number,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.ingestion_lag_breach",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("mode", mode),
      str("gateway_id", gatewayId),
      int("ingestion_lag_p95_ms", p95Ms),
    ],
    status: { code: 2 },
  };
}

/**
 * Issue #659 — build the duration-encoded observer.haiku_analysis span. As with
 * buildIngestionLagSpan, the latency is carried by start/end nanos (end=now,
 * start=now−duration) rather than an attribute, so spanmetrics produces a real
 * duration histogram. `Math.max(0, durationMs)` keeps the histogram honest: a
 * clock-skew or sub-ms call never yields a negative-duration span. Only
 * low-cardinality dimensions (env/mode/gateway_id/analysis.outcome/
 * analysis.shadow + the GenAI model dims); status mirrors analysis.outcome so
 * the failure series rolls into traces_spanmetrics_* as ERROR.
 */
function buildHaikuAnalysisSpan(
  env_: string,
  mode: string,
  gatewayId: string,
  durationMs: number,
  outcome: "ok" | "error",
  model: string,
  shadow: boolean,
): OtlpSpan {
  const endMs = Date.now();
  const startMs = endMs - Math.max(0, durationMs);
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.haiku_analysis",
    kind: 1,
    startTimeUnixNano: String(startMs * 1_000_000),
    endTimeUnixNano: String(endMs * 1_000_000),
    attributes: [
      str("env", env_),
      str("mode", mode),
      str("gateway_id", gatewayId),
      // GenAI semantic-convention dims — attribute the latency series to the
      // provider + model behind it.
      str("gen_ai.system", "anthropic"),
      str("gen_ai.request.model", model),
      str("analysis.outcome", outcome),
      // Distinguishes the primary analysis call from the shadow-chain call so
      // the two call sites produce queryable, separable spans.
      bool("analysis.shadow", shadow),
      // Raw model-call latency, also carried as an attribute for triage. A value
      // of `0` means the call resolved within the Date.now() resolution window
      // (< 1 ms) — NOT that it was skipped; TraceQL filters using
      // `durationMs > 0` should be aware they exclude these honest sub-ms calls.
      int("durationMs", durationMs),
    ],
    status: { code: outcome === "error" ? 2 : 1 },
  };
}

function buildPoisonSpan(env_: string, mode: string, gatewayId: string): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.queue_poison",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("mode", mode),
      str("gateway_id", gatewayId),
      str("reason", "poison"),
    ],
    status: { code: 2 },
  };
}

/**
 * ADR-065 #13 — one span per orphaned-agent trace fast-failed by the consumer
 * (missing-agent FK 23503, acked instead of dead-lettered). Separate span name
 * from queue_poison so the orphan-drain rate (a fleet-provisioning signal, #17)
 * is alertable independently of malformed-input poison.
 */
function buildOrphanSpan(env_: string, mode: string, gatewayId: string): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.queue_orphan",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("mode", mode),
      str("gateway_id", gatewayId),
      str("reason", "agent_fk_absent"),
    ],
    status: { code: 2 },
  };
}

/**
 * ADR-043 — emit a counter-style breach span when a depth gauge crosses
 * its threshold. Spanmetrics rolls these into per-name `traces_spanmetrics_*`
 * series; alert rules become PromQL `rate(...) > 0` mirrors of
 * ObserverPoisonAckRate. status=ERROR matches the poison-span convention.
 */
function buildDepthBreachSpan(
  name: "observer.queue_backlog_breach" | "observer.queue_dlq_breach",
  env_: string,
  gatewayId: string,
  d: QueueDepth,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name,
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("queue", d.queue),
      str("gateway_id", gatewayId),
      int("depth", d.messages),
    ],
    status: { code: 2 },
  };
}

/**
 * ADR-043 — counter-style breach span for consumer lag SLO breaches.
 * Emitted only when a queue_batch's `oldest_message_lag_ms` exceeds the
 * threshold. Carries the breached value for triage; alert rule fires on
 * rate(...) > 0 against `traces_spanmetrics_calls_total`.
 */
function buildLagBreachSpan(
  env_: string,
  mode: string,
  gatewayId: string,
  lagMs: number,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.queue_consumer_lag_breach",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("mode", mode),
      str("gateway_id", gatewayId),
      int("oldest_message_lag_ms", lagMs),
    ],
    status: { code: 2 },
  };
}

/**
 * MNE-1138 / ADR-043 — counter-style breach span for a message disposition
 * bucket (backpressure|orphan|poison). Emitted once per dirty batch per bucket
 * so rate(...)>0 alerts fire on the first non-zero count. `count` is the raw
 * batch total for that bucket (triage; the alert doesn't need it).
 */
function buildMessageDispositionBreachSpan(
  env_: string,
  mode: string,
  gatewayId: string,
  disposition: "backpressure" | "orphan" | "poison",
  count: number,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.message_disposition_breach",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("mode", mode),
      str("gateway_id", gatewayId),
      str("disposition", disposition),
      int("count", count),
    ],
    status: { code: 2 },
  };
}

function buildBacklogSpan(env_: string, gatewayId: string, d: QueueDepth): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.queue_backlog",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("queue", d.queue),
      str("gateway_id", gatewayId),
      int("depth", d.messages),
    ],
    status: { code: 1 },
  };
}

/**
 * ADR-064 W5 — the gateway-backlog gauge span. Carries depth, oldest-log age,
 * and net drain rate as numeric attributes for TraceQL dashboards. Null fields
 * are simply omitted so a partial CF response still yields a usable span.
 */
function buildGatewayBacklogSpan(env_: string, gatewayId: string, s: GatewayLogStats): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.gateway_backlog",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [str("env", env_), str("gateway_id", gatewayId), ...gatewayStatAttrs(s)],
    status: { code: 1 },
  };
}

/**
 * ADR-043 — counter-style breach span for the gateway-backlog gauges. Rolls
 * into per-name `traces_spanmetrics_*` series so the alert rule is the same
 * PromQL `rate(...) > 0` shape as ObserverPoisonAckRate. status=ERROR matches
 * the breach-span convention.
 */
function buildGatewayBreachSpan(
  name: "observer.gateway_backlog_breach" | "observer.gateway_drain_stalled_breach",
  env_: string,
  gatewayId: string,
  s: GatewayLogStats,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name,
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [str("env", env_), str("gateway_id", gatewayId), ...gatewayStatAttrs(s)],
    status: { code: 2 },
  };
}

/**
 * ADR-064 W8 — counter-style span for a CF management-API circuit-breaker trip.
 * `cf_call` is the guard call-site label (list | body | delete | stats | queues
 * | graphql) so triage can see which path drove the throttling. status=ERROR
 * matches the breach-span convention.
 */
function buildCircuitOpenSpan(
  env_: string,
  gatewayId: string,
  cfCall: string,
  failures: number,
  threshold: number,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.cf_api_circuit_open",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("gateway_id", gatewayId),
      str("cf_call", cfCall),
      int("failures", failures),
      int("threshold", threshold),
    ],
    status: { code: 2 },
  };
}

/**
 * Issue #703 — ADR-043 counter-style span for a failed LLM reachability probe.
 * Emitted only on probe failure so rate(...)>0 means "probe is failing".
 * `is_rate_limited` rides as a string attribute so the alert description can
 * surface whether it is a quota event or a generic error. status=ERROR mirrors
 * the circuit-breaker and depth-breach span conventions.
 */
function buildLLMProbeFailedSpan(
  env_: string,
  gatewayId: string,
  isRateLimited: boolean,
): OtlpSpan {
  const nowNs = timeUnixNano();
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.llm_probe_failed",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: nowNs,
    attributes: [
      str("env", env_),
      str("gateway_id", gatewayId),
      str("is_rate_limited", String(isRateLimited)),
    ],
    status: { code: 2 },
  };
}

/**
 * Issue #660 — the `observer.submit_trace` span. Its duration spans the measured
 * DB-write time (start = now − durationMs, end = now) so it yields a native
 * spanmetrics duration histogram; the same value rides as the `durationMs`
 * attribute for triage. Only low-cardinality dimensions (env, cell_id, and the
 * `submit.outcome` enum). status=ERROR for the two failing outcomes so they roll
 * into the per-name `traces_spanmetrics_*` series.
 */
function buildSubmitTraceSpan(
  env_: string,
  cellId: string,
  outcome: SubmitTraceOutcome,
  durationMs: number,
): OtlpSpan {
  const safeMs = Math.max(0, Math.round(durationMs));
  const endMs = Date.now();
  const startMs = endMs - safeMs;
  const isError = outcome === "orphan_fk" || outcome === "transient_error";
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.submit_trace",
    kind: 1,
    startTimeUnixNano: String(startMs * 1_000_000),
    endTimeUnixNano: String(endMs * 1_000_000),
    attributes: [
      str("submit.outcome", outcome),
      str("env", env_),
      str("cell_id", cellId),
      int("durationMs", safeMs),
    ],
    status: { code: isError ? 2 : 1 },
  };
}

/**
 * Issue #688 — the `observer.llm_probe` span. Its duration spans the measured
 * Anthropic call wall-clock (start = now − durationMs, end = now) so it yields a
 * native spanmetrics duration histogram; the same value rides as the `durationMs`
 * attribute for triage. Only low-cardinality dimensions (`gen_ai.system`, the
 * `probe.outcome` enum, env). status=ERROR for a failed probe (`rate_limited`,
 * `error`) so it rolls into the per-name `traces_spanmetrics_*` series.
 */
function buildLLMProbeSpan(env_: string, outcome: LLMProbeOutcome, durationMs: number): OtlpSpan {
  const safeMs = Math.max(0, Math.round(durationMs));
  const endMs = Date.now();
  const startMs = endMs - safeMs;
  const isError = outcome !== "ok";
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.llm_probe",
    kind: 1,
    startTimeUnixNano: String(startMs * 1_000_000),
    endTimeUnixNano: String(endMs * 1_000_000),
    attributes: [
      str("gen_ai.system", "anthropic"),
      str("probe.outcome", outcome),
      str("env", env_),
      int("durationMs", safeMs),
    ],
    status: { code: isError ? 2 : 1 },
  };
}

/** Shared numeric attributes for the gateway-backlog spans; null fields omitted. */
function gatewayStatAttrs(s: GatewayLogStats): OtlpAttribute[] {
  const attrs: OtlpAttribute[] = [];
  if (s.backlogDepth !== null) attrs.push(int("depth", s.backlogDepth));
  if (s.oldestLogAgeMs !== null) attrs.push(int("oldest_log_age_ms", s.oldestLogAgeMs));
  // Net drain can be negative (backlog growing) — use a signed encoding so the
  // sign survives, unlike int() which clamps to ≥ 0.
  if (s.netDrainPerMin !== null) attrs.push(intSigned("net_drain_per_min", s.netDrainPerMin));
  return attrs;
}

/**
 * Exported for tests. Wraps a list of spans in the OTLP ResourceSpans envelope.
 */
export function buildOtlpSpansBody(spans: OtlpSpan[], scopeName: string): string {
  return JSON.stringify({
    resourceSpans: [
      {
        resource: {
          attributes: [{ key: "service.name", value: { stringValue: "mnemom-observer" } }],
        },
        scopeSpans: [
          {
            scope: { name: scopeName },
            spans,
          },
        ],
      },
    ],
  });
}

async function postSpans(
  env: MetricsEnv,
  spans: OtlpSpan[],
  scope = "observer.queue",
): Promise<void> {
  const body = buildOtlpSpansBody(spans, scope);
  try {
    await fetch(`${env.OTLP_ENDPOINT}/v1/traces`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(env.OTLP_AUTH ? { Authorization: env.OTLP_AUTH } : {}),
      },
      body,
      signal: AbortSignal.timeout(5_000),
    });
  } catch {
    // Swallowed — fire-and-forget posture.
  }
}

/**
 * Issue #689 — build the `observer.cron_tick` span. Low-cardinality source /
 * backlog_estimate dimensions; integer counts for Tempo triage. Does not carry
 * `env` or `gateway_id` — consistent with the original inline construction in
 * emitTickSummary. Optional ingestion-lag attrs are omitted when count === 0.
 */
function buildCronTickSpan(
  source: string,
  backlogEstimate: string,
  stats: CronTickStats,
): OtlpSpan {
  const nowMs = Date.now();
  const nowNs = String(nowMs * 1_000_000);
  const endNs = String(nowMs * 1_000_000 + 1_000_000);
  const attrs: OtlpAttribute[] = [
    str("observer.source", source),
    int("observer.logs_fetched", stats.logs_fetched),
    int("observer.logs_processed", stats.processed),
    int("observer.logs_errored", stats.errors),
    int("observer.logs_unidentified", stats.logs_unidentified),
    str("observer.backlog_estimate", backlogEstimate),
  ];
  if (stats.first_error_name) {
    attrs.push(str("observer.first_error_name", stats.first_error_name));
  }
  if (stats.first_error_message) {
    attrs.push(str("observer.first_error_message", stats.first_error_message));
  }
  if (stats.ingestion_lag_count != null && stats.ingestion_lag_count > 0) {
    attrs.push(
      int("ingestion_lag_p50_ms", stats.ingestion_lag_p50_ms ?? 0),
      int("ingestion_lag_p95_ms", stats.ingestion_lag_p95_ms ?? 0),
      int("ingestion_lag_max_ms", stats.ingestion_lag_max_ms ?? 0),
      int("ingestion_lag_sum_ms", stats.ingestion_lag_sum_ms ?? 0),
      int("ingestion_lag_count", stats.ingestion_lag_count),
    );
  }
  return {
    traceId: hex32(),
    spanId: hex16(),
    name: "observer.cron_tick",
    kind: 1,
    startTimeUnixNano: nowNs,
    endTimeUnixNano: endNs,
    attributes: attrs,
    status: { code: 1 },
  };
}

/**
 * Issue #689 — fire-and-forget `observer.cron_tick` span for one scheduled()
 * tick. Uses the "observer.health" scope (distinct from "observer.queue" used
 * by the queue-path spans) to group cron-health signals separately in Tempo.
 * No-ops when OTLP_ENDPOINT is unset. Never throws — matches the module's
 * fire-and-forget posture.
 *
 * `backlogEstimate` is the pre-computed string ("0" or ">=N") from the caller;
 * keeping the computation in index.ts avoids threading OBSERVER_MAX_LOGS into
 * MetricsEnv.
 */
export function emitCronTickSpan(
  env: MetricsEnv,
  source: string,
  backlogEstimate: string,
  stats: CronTickStats,
): void {
  if (!env.OTLP_ENDPOINT) return;
  const span = buildCronTickSpan(source, backlogEstimate, stats);
  void postSpans(env, [span], "observer.health");
}

// ============================================================================
// CF queue-state fetcher (REST listing → GraphQL backlog)
// ============================================================================

const CF_API_BASE = "https://api.cloudflare.com/client/v4";
const CF_GRAPHQL_ENDPOINT = `${CF_API_BASE}/graphql`;

// ---------------------------------------------------------------------------
// Gateway-log-store snapshot (ADR-064 W5)
// ---------------------------------------------------------------------------

/**
 * Fetch the gateway-backlog snapshot from the CF AI Gateway REST `/logs`
 * endpoint. A single oldest-first page of size 1 with meta_info=true yields
 * both signals at once:
 *   - backlogDepth   ← result_info.total_count (total logs awaiting drain)
 *   - oldestLogAgeMs ← now − result[0].created_at (the tail's age)
 *
 * Returns null on transport/HTTP error so the caller emits nothing that tick
 * (consistent with fetchQueueDepths). A 200 with an unrecognized body yields a
 * stats object with null fields rather than null, so a shape drift degrades to
 * "gauge with gaps" rather than silent total loss. netDrainPerMin is left null
 * here; reportGatewayBacklog fills it from KV. nowMs injectable for tests.
 *
 * Requires CF_API_TOKEN with AI Gateway read scope (same token fetchLogs uses).
 */
export async function fetchGatewayLogStats(
  env: MetricsEnv,
  nowMs: number = Date.now(),
): Promise<GatewayLogStats | null> {
  const url =
    `${CF_API_BASE}/accounts/${env.CF_ACCOUNT_ID}/ai-gateway/gateways/${env.GATEWAY_ID}/logs` +
    `?per_page=1&order_by=created_at&order_by_direction=asc&meta_info=true`;

  let res: Response;
  try {
    // W4 (ADR-064) — route through the CF-API rate-guard + circuit breaker.
    // No unguarded CF management-API calls. A rate-cap / open-breaker throw is
    // caught here and degrades to "no gauges this tick" (fail-open), same as a
    // transport error.
    res = await cfFetch(
      url,
      {
        headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
        signal: AbortSignal.timeout(5_000),
      },
      env,
      "stats",
    );
  } catch (err) {
    console.warn(`[observer/metrics] gateway-log fetch threw: ${describe(err)}`);
    return null;
  }
  if (!res.ok) {
    console.warn(`[observer/metrics] gateway-log fetch non-OK: ${res.status}`);
    return null;
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (err) {
    console.warn(`[observer/metrics] gateway-log parse threw: ${describe(err)}`);
    return null;
  }
  return extractGatewayLogStats(body, nowMs);
}

/**
 * Pull {backlogDepth, oldestLogAgeMs} out of a CF AI Gateway `/logs` response,
 * tolerating missing fields at every layer. Unparseable / future-dated
 * timestamps yield a null age (never a negative one). netDrainPerMin is always
 * null here — it's a cross-tick concern owned by computeNetDrainPerMin.
 *
 * Exported for tests.
 */
export function extractGatewayLogStats(body: unknown, nowMs: number): GatewayLogStats {
  const stats: GatewayLogStats = {
    backlogDepth: null,
    oldestLogAgeMs: null,
    netDrainPerMin: null,
  };
  if (!isObject(body)) return stats;

  const info = body.result_info;
  if (isObject(info) && typeof info.total_count === "number" && info.total_count >= 0) {
    stats.backlogDepth = info.total_count;
  }

  const result = body.result;
  if (Array.isArray(result) && result.length > 0 && isObject(result[0])) {
    const createdAt = result[0].created_at;
    if (typeof createdAt === "string") {
      const t = Date.parse(createdAt);
      if (!Number.isNaN(t)) {
        const age = nowMs - t;
        stats.oldestLogAgeMs = age >= 0 ? age : 0;
      }
    }
  }

  return stats;
}

/**
 * Net logs-drained-per-minute since the last tick, via a KV cross-tick delta.
 * Reads the previous {depth, ts} sample, computes (prevDepth − curDepth) /
 * elapsedMin, then writes the current sample for next time. Net of new
 * arrivals — answers "is the backlog actually shrinking?", the question
 * ADR-064 cares about ("flat backlog", "oldest-log age strictly decreases").
 *
 * Returns null (drain-rate unknown) when KV is unbound, on the first sample,
 * on any KV error, or when too little time has elapsed to divide safely. Never
 * throws — KV failures must not break metric emission. nowMs injectable for
 * tests. Exported for tests.
 */
export async function computeNetDrainPerMin(
  env: MetricsEnv,
  currentDepth: number,
  nowMs: number = Date.now(),
): Promise<number | null> {
  const kv = env.BILLING_CACHE;
  if (!kv) return null;
  const key = `observer:gw-backlog:${env.GATEWAY_ID}`;

  let prev: { depth: number; ts: number } | null = null;
  try {
    const raw = await kv.get(key);
    if (raw) {
      const parsed = JSON.parse(raw) as unknown;
      if (isObject(parsed) && typeof parsed.depth === "number" && typeof parsed.ts === "number") {
        prev = { depth: parsed.depth, ts: parsed.ts };
      }
    }
  } catch (err) {
    console.warn(`[observer/metrics] drain-rate KV read failed: ${describe(err)}`);
    prev = null;
  }

  // Persist the current sample regardless of whether we could compute a rate.
  // 2h TTL: a sample older than that is too stale to derive a meaningful rate
  // from, and self-expiry keeps the key from lingering after a gateway rename.
  try {
    await kv.put(key, JSON.stringify({ depth: currentDepth, ts: nowMs }), {
      expirationTtl: 7_200,
    });
  } catch (err) {
    console.warn(`[observer/metrics] drain-rate KV write failed: ${describe(err)}`);
  }

  if (!prev) return null;
  const elapsedMin = (nowMs - prev.ts) / 60_000;
  // Guard against zero/negative/absurd elapsed (clock skew, double-fire ticks):
  // require at least ~6s between samples before trusting a rate.
  if (elapsedMin < 0.1) return null;
  return (prev.depth - currentDepth) / elapsedMin;
}

/**
 * Fetch backlog + oldest-message-age for the main queue and its DLQ.
 *
 * Two-step resolution because the Analytics dataset keys queues by UUID, not
 * name:
 *   (1) GET /accounts/:id/queues → map queue-name → queue-id
 *   (2) POST /graphql queueBacklogAdaptiveGroups(queueId_in:[…]) → backlog
 *
 * Returns `null` on any failure at either step — fetch error, non-OK status,
 * GraphQL errors, or missing fields. The caller treats null as "no gauges this
 * tick". Requires CF_API_TOKEN with Queues:Read + Analytics:Read scopes.
 *
 * Queue-name convention matches mnemom-infra/queues.tf:
 *   prod:    mnemom-observer-records        + mnemom-observer-records-dlq
 *   staging: mnemom-observer-records-staging + mnemom-observer-records-staging-dlq
 *
 * Derived from GATEWAY_ID: "mnemom" → prod names, "mnemom-staging" → staging.
 */
export async function fetchQueueDepths(env: MetricsEnv): Promise<QueueDepth[] | null> {
  const names = queueNamesFor(env.GATEWAY_ID);
  if (!names) return null;

  const idMap = await resolveQueueIds(env, [names.main, names.dlq]);
  if (!idMap) return null;

  const mainId = idMap.get(names.main);
  const dlqId = idMap.get(names.dlq);
  // We still emit a row even if a queue wasn't found — a brand-new deploy
  // could race the listing. backlogMessages=0 is the right default.

  const ids = [mainId, dlqId].filter((x): x is string => typeof x === "string");
  const groups = ids.length > 0 ? await fetchBacklogGroups(env, ids) : [];
  if (groups === null) return null;

  return [labeledDepth("main", mainId, groups), labeledDepth("dlq", dlqId, groups)];
}

async function resolveQueueIds(
  env: MetricsEnv,
  wantedNames: string[],
): Promise<Map<string, string> | null> {
  let res: Response;
  try {
    // W4 (ADR-064) — route through the CF-API rate-guard; no unguarded CF
    // management-API calls. Guard throw → null (no gauges this tick), same as
    // the existing transport-error path below.
    res = await cfFetch(
      `${CF_API_BASE}/accounts/${env.CF_ACCOUNT_ID}/queues?per_page=100`,
      {
        headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` },
        signal: AbortSignal.timeout(5_000),
      },
      env,
      "queues",
    );
  } catch (err) {
    console.warn(`[observer/metrics] queue listing threw: ${describe(err)}`);
    return null;
  }
  if (!res.ok) {
    console.warn(`[observer/metrics] queue listing non-OK: ${res.status}`);
    return null;
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (err) {
    console.warn(`[observer/metrics] queue listing parse threw: ${describe(err)}`);
    return null;
  }

  return extractQueueIdMap(body, wantedNames);
}

async function fetchBacklogGroups(
  env: MetricsEnv,
  queueIds: string[],
): Promise<BacklogGroup[] | null> {
  // CF Analytics schema (verified 2026-04-24):
  //   queueBacklogAdaptiveGroups exposes only avg { messages, bytes,
  //   sampleInterval } — there is no `max` aggregate, no
  //   oldestMessageAgeSeconds field, and datetime is not orderable. The
  //   original Step 52 query used a stale schema and silently returned
  //   null on every tick. See ADR-033 for the lag-tracking pivot.
  const query = `
    query QueueBacklog($account: String!, $ids: [String!]!, $since: Time!) {
      viewer {
        accounts(filter: { accountTag: $account }) {
          queueBacklogAdaptiveGroups(
            filter: { queueId_in: $ids, datetime_geq: $since },
            limit: 100
          ) {
            dimensions { queueId }
            avg { messages }
          }
        }
      }
    }
  `;
  const sinceIso = new Date(Date.now() - 5 * 60_000).toISOString();

  let res: Response;
  try {
    // W4 (ADR-064) — guarded drop-in; cfFetch handles POST + body. Guard throw
    // → null (no gauges this tick), same as the transport-error path below.
    res = await cfFetch(
      CF_GRAPHQL_ENDPOINT,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.CF_API_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          query,
          variables: { account: env.CF_ACCOUNT_ID, ids: queueIds, since: sinceIso },
        }),
        signal: AbortSignal.timeout(5_000),
      },
      env,
      "graphql",
    );
  } catch (err) {
    console.warn(`[observer/metrics] backlog fetch threw: ${describe(err)}`);
    return null;
  }
  if (!res.ok) {
    console.warn(`[observer/metrics] backlog fetch non-OK: ${res.status}`);
    return null;
  }
  let body: unknown;
  try {
    body = await res.json();
  } catch (err) {
    console.warn(`[observer/metrics] backlog parse threw: ${describe(err)}`);
    return null;
  }
  return extractBacklogGroups(body);
}

function labeledDepth(
  label: "main" | "dlq",
  queueId: string | undefined,
  groups: BacklogGroup[],
): QueueDepth {
  const row = queueId ? groups.find((g) => g.queueId === queueId) : undefined;
  return {
    queue: label,
    messages: row?.messages ?? 0,
  };
}

// ============================================================================
// Helpers
// ============================================================================

function envLabel(env: MetricsEnv): "production" | "staging" | "unknown" {
  if (env.GATEWAY_ID === "mnemom") return "production";
  if (env.GATEWAY_ID === "mnemom-staging") return "staging";
  return "unknown";
}

/**
 * MNE-892 — the logical cell this Worker serves (single fixed enum `us-1`
 * today). Mirrors index.ts:resolveCellId; kept local so metrics.ts can stamp
 * `cell_id` on the OTLP resource without importing from index.ts (which would
 * create a metrics↔index import cycle). A blank/whitespace override falls back
 * to "us-1" so a hollow var never yields an empty cell_id.
 */
function resolveCellId(env: MetricsEnv): string {
  return env.CELL_ID?.trim() || "us-1";
}

function str(key: string, value: string): OtlpAttribute {
  return { key, value: { stringValue: value } };
}

function int(key: string, value: number): OtlpAttribute {
  return { key, value: { intValue: String(Math.max(0, Math.floor(value))) } };
}

/** Like int() but preserves sign — net drain rate can be negative (growing). */
function intSigned(key: string, value: number): OtlpAttribute {
  return { key, value: { intValue: String(Math.trunc(value)) } };
}

function bool(key: string, value: boolean): OtlpAttribute {
  return { key, value: { boolValue: value } };
}

function hex32(): string {
  return crypto.randomUUID().replace(/-/g, "");
}

function hex16(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 16);
}

function timeUnixNano(): string {
  return String(Date.now() * 1_000_000);
}

function describe(err: unknown): string {
  return err instanceof Error ? `${err.name}: ${err.message}` : String(err);
}

function queueNamesFor(gatewayId: string): { main: string; dlq: string } | null {
  if (gatewayId === "mnemom") {
    return {
      main: "mnemom-observer-records",
      dlq: "mnemom-observer-records-dlq",
    };
  }
  if (gatewayId === "mnemom-staging") {
    return {
      main: "mnemom-observer-records-staging",
      dlq: "mnemom-observer-records-staging-dlq",
    };
  }
  return null;
}

interface BacklogGroup {
  queueId: string;
  messages: number;
}

/**
 * Pull the flat list of {queueId, messages} rows out of the CF GraphQL
 * response, tolerating missing fields at every layer. Returns null if the
 * response shape is unrecognizable.
 *
 * Schema reference (verified 2026-04-24):
 *   queueBacklogAdaptiveGroups[].avg.messages — uint64
 *
 * Exported for tests.
 */
export function extractBacklogGroups(body: unknown): BacklogGroup[] | null {
  if (!isObject(body)) return null;
  const data = body.data;
  if (!isObject(data) || !isObject(data.viewer)) return null;
  const accounts = data.viewer.accounts;
  if (!Array.isArray(accounts) || accounts.length === 0) return null;

  const rows: BacklogGroup[] = [];
  for (const acct of accounts) {
    if (!isObject(acct)) continue;
    const groups = acct.queueBacklogAdaptiveGroups;
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      if (!isObject(g)) continue;
      const dims = isObject(g.dimensions) ? g.dimensions : undefined;
      const avg = isObject(g.avg) ? g.avg : undefined;
      const queueId = typeof dims?.queueId === "string" ? dims.queueId : null;
      if (!queueId) continue;
      rows.push({
        queueId,
        messages: typeof avg?.messages === "number" ? avg.messages : 0,
      });
    }
  }

  return rows;
}

/**
 * Pull {name → id} for the names we asked about out of the CF /queues REST
 * response. Tolerates every layer being missing.
 *
 * Exported for tests.
 */
export function extractQueueIdMap(body: unknown, wantedNames: string[]): Map<string, string> {
  const out = new Map<string, string>();
  if (!isObject(body)) return out;
  const result = body.result;
  if (!Array.isArray(result)) return out;
  for (const q of result) {
    if (!isObject(q)) continue;
    const name = typeof q.queue_name === "string" ? q.queue_name : null;
    const id = typeof q.queue_id === "string" ? q.queue_id : null;
    if (!name || !id) continue;
    if (wantedNames.includes(name)) out.set(name, id);
  }
  return out;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}
