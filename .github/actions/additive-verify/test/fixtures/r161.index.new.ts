/**
 * Mnemom Risk Worker — Cloudflare Worker entry point.
 *
 * Handles all /v1/risk/* HTTP routes for individual and team
 * risk assessment, history, and ZK proof retrieval.
 */

import type { RiskEnv } from "./types";
import {
  emitRiskAssessSpan,
  emitTeamRiskAssessSpan,
  emitRequestSpan,
  emitDbHealthSpan,
} from "./metrics";
import { getRiskSupabaseCircuitBreaker } from "./supabase";
import {
  handleAssessRisk,
  handleAssessTeamRisk,
  handleGetAssessment,
  handleGetHistory,
  handleGetTeamAssessment,
  handleGetTeamHistory,
  handleGetProof,
  resolveAccountId,
  errorResponse,
} from "./handlers";

// ============================================
// JWT auth helper (matches mnemom-reputation pattern)
// ============================================

interface JWTPayload {
  sub: string;
  email?: string;
  role?: string;
  app_metadata?: { is_admin?: boolean };
  exp: number;
  iat: number;
}

interface JWTHeader {
  alg?: string;
  typ?: string;
}

/** Decode a base64url segment (JWT-style: '-'/'_' alphabet, no padding) to bytes. */
function base64urlToBytes(segment: string): Uint8Array {
  const b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64urlToString(segment: string): string {
  return new TextDecoder().decode(base64urlToBytes(segment));
}

/**
 * Verify a Supabase access token: HS256 signature against SUPABASE_JWT_SECRET,
 * then the `exp` claim. Returns the payload on success, or null for any
 * malformed/forged/expired/downgraded token. Fails closed if the secret is
 * unset — never skip verification silently.
 *
 * Supabase access tokens are HS256-signed with the project JWT secret; we
 * reject any other `alg` (incl. "none" and RS256) to block downgrade attacks,
 * and verify the signature with Web Crypto (no node:crypto on Workers).
 */
export async function parseJWT(request: Request, env: RiskEnv): Promise<JWTPayload | null> {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader?.startsWith("Bearer ")) return null;

  const secret = env.SUPABASE_JWT_SECRET;
  if (!secret) {
    // Fail closed: a missing secret means we cannot verify — reject rather
    // than fall back to an unauthenticated/unverified decode.
    console.warn("parseJWT: SUPABASE_JWT_SECRET is unset — rejecting all tokens (fail closed)");
    return null;
  }

  const token = authHeader.slice(7);
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signatureB64] = parts;

    // Reject anything that isn't HS256 (blocks alg:none / RS256 downgrade).
    const header = JSON.parse(base64urlToString(headerB64)) as JWTHeader;
    if (header.alg !== "HS256") return null;

    // Verify the HMAC-SHA-256 signature over `${header}.${payload}`.
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const signature = base64urlToBytes(signatureB64);
    const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const valid = await crypto.subtle.verify("HMAC", key, signature, data);
    if (!valid) return null;

    // Signature is good — now enforce expiry (and any future claim checks).
    const payload = JSON.parse(base64urlToString(payloadB64)) as JWTPayload;
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

// ============================================
// Route templating for golden-signal spans (MNE-721)
// ============================================

/**
 * Map a concrete request path to its low-cardinality route TEMPLATE for the
 * per-request span's `http_route` attribute. Dynamic IDs are collapsed to
 * `:param` so spanmetrics series don't explode (observability-architecture.md
 * cardinality discipline). Unknown paths bucket to "unmatched" (a 404), never
 * the raw path. (Routes are unambiguous by path alone in this service, so the
 * HTTP method is not needed to disambiguate the template.)
 */
export function routeTemplate(path: string): string {
  if (path === "/health") return "/health";
  if (path === "/v1/risk/assess") return "/v1/risk/assess";
  if (path === "/v1/risk/assess/team") return "/v1/risk/assess/team";
  if (/^\/v1\/risk\/assessments\/[^/]+$/.test(path)) return "/v1/risk/assessments/:id";
  if (/^\/v1\/risk\/history\/[^/]+$/.test(path)) return "/v1/risk/history/:agent_id";
  if (/^\/v1\/risk\/team-assessments\/[^/]+$/.test(path)) return "/v1/risk/team-assessments/:id";
  if (/^\/v1\/risk\/team-history\/[^/]+$/.test(path)) return "/v1/risk/team-history/:team_id";
  if (/^\/v1\/risk\/proofs\/[^/]+$/.test(path)) return "/v1/risk/proofs/:id";
  return "unmatched";
}

// ============================================
// Worker export
// ============================================

export default {
  async fetch(request: Request, env: RiskEnv, ctx: ExecutionContext): Promise<Response> {
    // Handle CORS preflight (no golden-signal span — preflight is not a work
    // request and would inflate the traffic SLI).
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // MNE-721: one `mnemom.risk.request` span per request → traffic + latency +
    // error-rate golden signals for the whole service (every route), not just
    // the assess path. Flushed off the response path via ctx.waitUntil; status
    // resolved from the response (or 500 on an unexpected throw).
    const startMs = Date.now();
    const emitSpan = (status: number): void => {
      ctx.waitUntil(
        emitRequestSpan(env, {
          route: routeTemplate(path),
          method,
          status,
          durationMs: Date.now() - startMs,
        }),
      );
    };

    try {
      const response = await dispatch(request, env, ctx, url, path, method);
      emitSpan(response.status);
      return response;
    } catch (err) {
      // Log the raw error server-side; return a generic message to the client
      // (never echo internal exception text — info-leak, GA discipline).
      console.error("Unexpected error:", err);
      emitSpan(500);
      return errorResponse("An internal error occurred", 500);
    }
  },

  /**
   * Low-frequency saturation seam (MNE-722). On each cron tick, sample the live
   * Supabase circuit-breaker and emit one `mnemom.risk.db_health` heartbeat —
   * risk's 4th golden signal (saturation/capacity), parity with the sibling
   * mnemom-reputation Worker. No-op when OTLP_ENDPOINT is unset; flushed off the
   * critical path via ctx.waitUntil, mirroring how `fetch` flushes its spans.
   *
   * The PRIMARY signal here is heartbeat PRESENCE/ABSENCE: a missing span means
   * the cron never fired / the Worker is dark.
   *
   * Note: if this isolate is cold (no recent fetch traffic), the breaker state
   * reflects the initial fresh instance (closed / failures=0), not the live
   * state of a request-processing isolate — Cloudflare may run this cron in a
   * separate isolate from the one accumulating failures on the fetch path. So
   * under low-traffic conditions a 'closed' heartbeat means "Worker is alive",
   * NOT a "DB is healthy" guarantee. This matches reputation's known limitation.
   */
  async scheduled(
    _controller: ScheduledController,
    env: RiskEnv,
    ctx: ExecutionContext,
  ): Promise<void> {
    ctx.waitUntil(emitDbHealthSpan(env, getRiskSupabaseCircuitBreaker()));
  },
};

/**
 * Route dispatch — every /v1/risk/* route. Extracted from `fetch` so the
 * per-request golden-signal span (MNE-721) can wrap a single exit point.
 */
async function dispatch(
  request: Request,
  env: RiskEnv,
  ctx: ExecutionContext,
  url: URL,
  path: string,
  method: string,
): Promise<Response> {
  // GET /health
  if (path === "/health" && method === "GET") {
    return new Response(JSON.stringify({ status: "ok" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }

  // --- Authenticated POST routes ---

  // POST /v1/risk/assess
  if (path === "/v1/risk/assess" && method === "POST") {
    const user = await parseJWT(request, env);
    if (!user) return errorResponse("Authentication required", 401);
    // SLA Wave 2: emit a mnemom.risk.assess span (span-derived SLI for the
    // ops risk_assess scenario). 5xx = service failure; 4xx = caller fault.
    // No-op until OTLP_ENDPOINT is set; flushed off the response path.
    const assessResponse = await handleAssessRisk(request, env, user.sub);
    ctx.waitUntil(emitRiskAssessSpan(env, assessResponse.status));
    return assessResponse;
  }

  // POST /v1/risk/assess/team
  if (path === "/v1/risk/assess/team" && method === "POST") {
    const user = await parseJWT(request, env);
    if (!user) return errorResponse("Authentication required", 401);
    const teamAssessResponse = await handleAssessTeamRisk(request, env, user.sub);
    ctx.waitUntil(emitTeamRiskAssessSpan(env, teamAssessResponse.status));
    return teamAssessResponse;
  }

  // --- Authenticated GET routes ---
  // Every read endpoint requires a JWT and is tenant-scoped by the caller's
  // billing account_id (resolved once here). Anonymous → 401; a row owned by
  // another account → 404 (single-record) or an empty collection (history).

  // GET /v1/risk/assessments/:id
  const assessmentMatch = path.match(/^\/v1\/risk\/assessments\/([^/]+)$/);
  if (assessmentMatch && method === "GET") {
    const user = await parseJWT(request, env);
    if (!user) return errorResponse("Authentication required", 401);
    const accountId = await resolveAccountId(env, user.sub);
    return handleGetAssessment(assessmentMatch[1], accountId, env);
  }

  // GET /v1/risk/history/:agent_id
  const historyMatch = path.match(/^\/v1\/risk\/history\/([^/]+)$/);
  if (historyMatch && method === "GET") {
    const user = await parseJWT(request, env);
    if (!user) return errorResponse("Authentication required", 401);
    const accountId = await resolveAccountId(env, user.sub);
    return handleGetHistory(historyMatch[1], accountId, env, url);
  }

  // GET /v1/risk/team-assessments/:id
  const teamAssessmentMatch = path.match(/^\/v1\/risk\/team-assessments\/([^/]+)$/);
  if (teamAssessmentMatch && method === "GET") {
    const user = await parseJWT(request, env);
    if (!user) return errorResponse("Authentication required", 401);
    const accountId = await resolveAccountId(env, user.sub);
    return handleGetTeamAssessment(teamAssessmentMatch[1], accountId, env);
  }

  // GET /v1/risk/team-history/:team_id
  const teamHistoryMatch = path.match(/^\/v1\/risk\/team-history\/([^/]+)$/);
  if (teamHistoryMatch && method === "GET") {
    const user = await parseJWT(request, env);
    if (!user) return errorResponse("Authentication required", 401);
    const accountId = await resolveAccountId(env, user.sub);
    return handleGetTeamHistory(teamHistoryMatch[1], accountId, env, url);
  }

  // GET /v1/risk/proofs/:id
  const proofMatch = path.match(/^\/v1\/risk\/proofs\/([^/]+)$/);
  if (proofMatch && method === "GET") {
    const user = await parseJWT(request, env);
    if (!user) return errorResponse("Authentication required", 401);
    const accountId = await resolveAccountId(env, user.sub);
    return handleGetProof(proofMatch[1], accountId, env);
  }

  return errorResponse("Not found", 404);
}
