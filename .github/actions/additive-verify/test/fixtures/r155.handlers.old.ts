/**
 * HTTP route handlers for the Risk Engine microservice (E-08).
 *
 * Follows the handler pattern from mnemom-reputation:
 * - Imported Supabase helpers
 * - Exported async handler functions
 * - jsonResponse / errorResponse helpers
 * - KV caching via dedicated cache module
 */

import {
  supabaseRpc,
  supabaseQuery,
  supabaseInsert,
  classifyPostgrestError,
} from './supabase';
import { toSpecAssessment, toSpecTeamAssessment } from './spec-shape';
import { buildErrorBody } from './http-errors';
import { kvGet, kvPut } from './cache';
import { computeIndividualRisk } from './engine';
import { computeTeamRisk } from './team-engine';
import type { AgentInput, PairwiseCoherenceData, TeamCardData } from './team-engine';
import { requestRiskProof } from './proving';
import type { RiskEnv } from './types';
import type { RiskTolerance } from '@mnemom/types';

// ============================================
// Response helpers
// ============================================

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}

/**
 * Emit a canonical error envelope (post-#582 ADR-API-001 conv 1):
 *   { error: { code: "<machine_code>", message: "<human prose>", details?: any } }
 *
 * `code` defaults to a status-class machine code (see http-errors.ts's
 * STATUS_CODE_MAP); callers may override (e.g. 'feature_gated', 'invalid_uuid').
 * `details` is carried through when supplied. Callers that don't pass code/
 * details get the same flat-feeling API but emit the structured envelope.
 */
export function errorResponse(
  message: string,
  status: number,
  code?: string,
  details?: unknown,
): Response {
  return jsonResponse(buildErrorBody(message, status, code, details), status);
}

// ============================================
// Feature gate helper
// ============================================

/**
 * Check if the authenticated user's plan includes a specific feature flag.
 * Returns null if allowed, or a 403 Response if gated.
 * Fail-open: if billing lookup fails, the request is allowed.
 */
/**
 * Check feature gate and resolve billing account_id.
 * Returns { gateResponse, accountId }.
 * gateResponse is null if allowed, or a 403 Response if gated.
 * accountId is the billing account_id (falls back to userId if lookup fails).
 */
async function checkFeatureAndResolveAccount(
  env: RiskEnv,
  userId: string,
  featureFlag: string,
): Promise<{ gateResponse: Response | null; accountId: string }> {
  const { data, error } = await supabaseRpc(env, 'admin_get_billing_summary', {
    p_user_id: userId,
  });

  if (error || !data) {
    // Fail-open: if we can't resolve billing, allow
    console.warn(`[feature-gate] Could not resolve billing for ${userId}: ${error}`);
    return { gateResponse: null, accountId: userId };
  }

  const summary = data as Record<string, unknown>;
  const account = summary.account as Record<string, unknown> | undefined;
  const accountId = (account?.account_id as string) ?? userId;
  const plan = summary.plan as Record<string, unknown> | undefined;
  const featureFlags = (plan?.feature_flags ?? {}) as Record<string, boolean>;

  if (featureFlags[featureFlag]) {
    return { gateResponse: null, accountId };
  }

  return {
    gateResponse: new Response(JSON.stringify(buildErrorBody(
      `This feature requires a plan with ${featureFlag} enabled.`,
      403,
      'feature_gated',
      { feature: featureFlag, upgrade_url: '/pricing' },
    )), {
      status: 403,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
      },
    }),
    accountId,
  };
}

// ============================================
// 1. POST /v1/risk/assess
// ============================================

export async function handleAssessRisk(
  request: Request,
  env: RiskEnv,
  userId: string,
): Promise<Response> {
  // Parse body
  let body: {
    agent_id?: string;
    source?: string;
    context?: {
      action_type?: string;
      amount?: number;
      counterparty_id?: string;
      use_case?: string;
      risk_tolerance?: string;
    };
  };
  try {
    body = await request.json() as typeof body;
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const agentId = body.agent_id;
  const ctx = body.context;

  if (!agentId) return errorResponse('agent_id is required', 400);
  if (!ctx?.action_type) return errorResponse('context.action_type is required', 400);

  const actionType = ctx.action_type;
  const validActions = [
    'financial_transaction', 'data_access', 'task_delegation',
    'tool_invocation', 'autonomous_operation', 'multi_agent_coordination',
  ];
  if (!validActions.includes(actionType)) {
    return errorResponse(`Invalid action_type: ${actionType}`, 400);
  }

  const riskTolerance = (ctx.risk_tolerance ?? 'moderate') as RiskTolerance;
  const source = body.source === 'playground' ? 'playground' : 'api';

  // Feature gate + resolve billing account
  const { gateResponse, accountId } = await checkFeatureAndResolveAccount(env, userId, 'risk_assessment');
  if (gateResponse) return gateResponse;

  // Check KV cache (key includes all scoring inputs)
  const amt = ctx.amount ?? 0;
  const cacheKey = `risk:${agentId}:${actionType}:${riskTolerance}:${amt}`;
  const cached = await kvGet<Record<string, unknown>>(env, cacheKey);
  if (cached) return jsonResponse(cached);

  // Fetch reputation
  const { data: repData, error: repError } = await supabaseQuery(env, 'reputation_scores', {
    filters: { agent_id: agentId },
    single: true,
  });

  if (repError) {
    console.error('[risk] reputation lookup failed:', repError);
    return errorResponse('A database error occurred', 500);
  }
  if (!repData) return errorResponse('Reputation score not found for this agent', 404);

  const rep = repData as Record<string, unknown>;
  const reputation = {
    integrity_ratio: (rep.integrity_ratio_score as number) ?? 500,
    compliance: (rep.compliance_score as number) ?? 500,
    drift_stability: (rep.drift_stability_score as number) ?? 500,
    trace_completeness: (rep.trace_completeness_score as number) ?? 500,
    coherence_compatibility: (rep.coherence_compatibility_score as number) ?? 500,
    score: (rep.score as number) ?? 500,
    confidence: (rep.confidence as 'insufficient' | 'low' | 'medium' | 'high') ?? 'low',
  };

  // Fetch recent violations
  const { data: violationData } = await supabaseQuery(env, 'reputation_events', {
    filters: { agent_id: agentId },
    rawFilters: ['event_type=eq.violation_detected'],
    order: 'timestamp.desc',
    limit: 100,
  });

  const violations = ((violationData ?? []) as Record<string, unknown>[]).map(v => ({
    severity: (v.severity as 'low' | 'medium' | 'high' | 'critical') ?? 'low',
    created_at: (v.timestamp as string) ?? (v.created_at as string) ?? new Date().toISOString(),
  }));

  // Compute risk
  const assessmentCtx = {
    action_type: actionType as import('@mnemom/types').ActionType,
    risk_tolerance: riskTolerance,
    amount: ctx.amount as number | undefined,
  };
  const result = computeIndividualRisk(reputation, violations, assessmentCtx, Date.now());

  // Generate assessment ID
  const assessmentId = `ra-${crypto.randomUUID().slice(0, 8)}`;

  // Build full assessment (engine/DB shape) + spec-shape (returned to clients).
  const assessment = {
    assessment_id: assessmentId,
    agent_id: agentId,
    ...result,
    proof_id: null as string | null,
    proof_status: 'none' as const,
    created_at: new Date().toISOString(),
  };
  const specAssessment = toSpecAssessment(assessment);

  // Persist assessment — must succeed before caching
  const { error: insertError } = await supabaseInsert(env, 'risk_assessments', {
    assessment_id: assessmentId,
    agent_id: agentId,
    account_id: accountId,
    action_type: actionType,
    context: ctx,
    risk_score: result.risk_score,
    risk_level: result.risk_level,
    recommendation: result.recommendation,
    confidence: result.confidence,
    contributing_factors: result.contributing_factors,
    suggested_thresholds: result.suggested_thresholds,
    explanation: result.explanation,
    reputation_snapshot: reputation,
    recency_data: violations,
    source,
  });

  if (insertError) {
    // Persisted-store write failed but the assessment itself is valid. Signal
    // the partial success with a boolean flag; log the raw error server-side
    // only (never echo internal DB text to the client — info-leak). Don't
    // cache failed inserts.
    console.error('[handleAssessRisk] Insert error:', insertError);
    return jsonResponse({ ...specAssessment, _persistence_failed: true });
  }

  // Insert metering event (non-blocking, fail-open)
  const meteringEventId = `me-${crypto.randomUUID().slice(0, 8)}`;
  supabaseInsert(env, 'metering_events', {
    event_id: meteringEventId,
    account_id: accountId,
    agent_id: agentId,
    event_type: 'risk_assessment_individual',
    metadata: { assessment_id: assessmentId, action_type: actionType },
  }).catch(() => { /* fail-open */ });

  // Fire-and-forget ZK proof if prover is configured
  if (env.PROVER_URL) {
    requestRiskProof(env, assessmentId, 'individual_risk', {
      reputation,
      violations,
      context: assessmentCtx,
      now_ms: Date.now(),
    }).catch(() => { /* fail-open */ });
  }

  // Only cache after successful persistence (cache the spec shape so cache
  // hits don't re-emit the DB shape).
  await kvPut(env, cacheKey, specAssessment, 300);

  return jsonResponse(specAssessment);
}

// ============================================
// 2. POST /v1/risk/assess/team
// ============================================

export async function handleAssessTeamRisk(
  request: Request,
  env: RiskEnv,
  userId: string,
): Promise<Response> {
  // Parse body. The `context` object is persisted verbatim to
  // team_risk_assessments.context (JSONB), so additional fields beyond
  // what we explicitly consume flow through to storage for audit /
  // dashboarding use.
  //
  // Coherence-vector fields (governance_median, conflict_edge_count,
  // conscience_universal) are emitted by mnemom-api's
  // handleExtractFaultLines when `trigger === 'coherence_check'`, per
  // ADR-025 / mnemom-api migration 127. They are typed here for
  // documentation + to surface field-name typos at compile time; the
  // risk engine does not yet consume them in scoring.
  let body: {
    agent_ids?: string[];
    team_id?: string;
    source?: string;
    context?: {
      action_type?: string;
      amount?: number;
      counterparty_id?: string;
      use_case?: string;
      risk_tolerance?: string;
      team_task?: string;
      coordination_mode?: string;
      // Coherence-vector context from mnemom-api (ADR-025)
      trigger?: string;
      governance_median?: number | null;
      conflict_edge_count?: number;
      conscience_universal?: boolean | null;
    };
  };
  try {
    body = await request.json() as typeof body;
  } catch {
    return errorResponse('Invalid JSON body', 400);
  }

  const ctx = body.context;
  const teamId = body.team_id;
  let agentIds: string[];
  let teamCardData: TeamCardData | undefined;

  // --- Resolve agent_ids: either from team_id or direct ---
  if (teamId && body.agent_ids) {
    return errorResponse('Cannot specify both team_id and agent_ids', 400);
  }

  if (teamId) {
    // team_id path: resolve agents and team card from team tables
    const { data: teamData, error: teamError } = await supabaseQuery(env, 'teams', {
      filters: { id: teamId },
      single: true,
    });
    if (teamError) {
      console.error('[risk] team lookup failed:', teamError);
      return errorResponse('A database error occurred', 500);
    }
    if (!teamData) return errorResponse('Team not found', 404);
    const team = teamData as Record<string, unknown>;
    if (team.archived_at) return errorResponse('Team is archived', 400);

    // Fetch active members
    const { data: memberRows, error: memberError } = await supabaseQuery(env, 'team_members', {
      filters: { team_id: teamId },
      rawFilters: ['removed_at=is.null'],
      select: 'agent_id',
    });
    if (memberError) {
      console.error('[risk] team members lookup failed:', memberError);
      return errorResponse('A database error occurred', 500);
    }
    agentIds = ((memberRows ?? []) as Record<string, unknown>[]).map(r => r.agent_id as string);
    if (agentIds.length < 2) return errorResponse('Team must have at least 2 active members', 400);

    // Fetch active alignment card for team
    const { data: cardData } = await supabaseQuery(env, 'alignment_cards', {
      filters: { team_id: teamId },
      rawFilters: ['is_active=eq.true'],
      single: true,
    });
    if (cardData) {
      const card = cardData as Record<string, unknown>;
      const cardJson = card.card_json as Record<string, unknown> | undefined;
      const values = cardJson?.values as Record<string, unknown> | undefined;
      const declared = values?.declared;
      if (Array.isArray(declared) && declared.length > 0) {
        teamCardData = { declared_values: declared.map(String) };
      }
    }
  } else {
    // agent_ids path (original)
    if (!body.agent_ids || !Array.isArray(body.agent_ids)) {
      return errorResponse('agent_ids must be an array', 400);
    }
    agentIds = body.agent_ids;
  }

  if (agentIds.length < 2) return errorResponse('At least 2 agents required for team assessment', 400);
  if (agentIds.length > 50) return errorResponse('Maximum 50 agents per team assessment', 400);
  if (!ctx?.action_type) return errorResponse('context.action_type is required', 400);

  const actionType = ctx.action_type;
  const validActions = [
    'financial_transaction', 'data_access', 'task_delegation',
    'tool_invocation', 'autonomous_operation', 'multi_agent_coordination',
  ];
  if (!validActions.includes(actionType)) {
    return errorResponse(`Invalid action_type: ${actionType}`, 400);
  }

  const riskTolerance = (ctx.risk_tolerance ?? 'moderate') as RiskTolerance;
  const source = body.source === 'playground' ? 'playground' : 'api';

  // Feature gate + resolve billing account
  const { gateResponse, accountId } = await checkFeatureAndResolveAccount(env, userId, 'team_risk_assessment');
  if (gateResponse) return gateResponse;

  // Batch fetch reputations for all agents
  const idList = agentIds.join(',');
  const { data: repRows, error: repError } = await supabaseQuery(env, 'reputation_scores', {
    rawFilters: [`agent_id=in.(${idList})`],
  });

  if (repError) {
    console.error('[risk] reputation lookup failed:', repError);
    return errorResponse('A database error occurred', 500);
  }

  const reputationMap = new Map<string, Record<string, unknown>>();
  for (const row of (repRows ?? []) as Record<string, unknown>[]) {
    reputationMap.set(row.agent_id as string, row);
  }

  // Build AgentInput[] for the team engine
  const agents: AgentInput[] = [];
  const violationsMap = new Map<string, Array<{ severity: 'low' | 'medium' | 'high' | 'critical'; created_at: string }>>();

  // Fetch alignment cards for declared values
  const { data: alignmentRows } = await supabaseQuery(env, 'alignment_cards', {
    rawFilters: [`agent_id=in.(${idList})`],
    select: 'agent_id,values,boundaries,priorities',
  });

  const alignmentMap = new Map<string, Record<string, unknown>>();
  for (const row of (alignmentRows ?? []) as Record<string, unknown>[]) {
    alignmentMap.set(row.agent_id as string, row);
  }

  for (const agentId of agentIds) {
    const rep = reputationMap.get(agentId);
    const alignment = alignmentMap.get(agentId);

    agents.push({
      agent_id: agentId,
      reputation: {
        integrity_ratio: (rep?.integrity_ratio_score as number) ?? 500,
        compliance: (rep?.compliance_score as number) ?? 500,
        drift_stability: (rep?.drift_stability_score as number) ?? 500,
        trace_completeness: (rep?.trace_completeness_score as number) ?? 500,
        coherence_compatibility: (rep?.coherence_compatibility_score as number) ?? 500,
        score: (rep?.score as number) ?? 500,
        confidence: (rep?.confidence as 'insufficient' | 'low' | 'medium' | 'high') ?? 'low',
      },
      declared_values: Array.isArray(alignment?.values)
        ? (alignment!.values as unknown[]).map(String)
        : undefined,
    });

    // Fetch violations for this agent
    const { data: violationData } = await supabaseQuery(env, 'reputation_events', {
      filters: { agent_id: agentId },
      rawFilters: ['event_type=eq.violation_detected'],
      order: 'timestamp.desc',
      limit: 100,
    });

    violationsMap.set(
      agentId,
      ((violationData ?? []) as Record<string, unknown>[]).map(v => ({
        severity: (v.severity as 'low' | 'medium' | 'high' | 'critical') ?? 'low',
        created_at: (v.timestamp as string) ?? (v.created_at as string) ?? new Date().toISOString(),
      })),
    );
  }

  // Fetch pairwise coherence data
  const { data: pairwiseRows } = await supabaseQuery(env, 'pairwise_coherence', {
    rawFilters: [
      `agent_a=in.(${idList})`,
      `agent_b=in.(${idList})`,
    ],
  });

  const pairwise: PairwiseCoherenceData[] = ((pairwiseRows ?? []) as Record<string, unknown>[]).map(row => ({
    agent_a: row.agent_a as string,
    agent_b: row.agent_b as string,
    value_overlap: (row.value_overlap as number) ?? 500,
    priority_alignment: (row.priority_alignment as number) ?? 500,
    behavioral_corr_penalty: (row.behavioral_corr_penalty as number) ?? 0,
    boundary_compatibility: (row.boundary_compatibility as number) ?? 500,
  }));

  // Compute team risk using the proper three-pillar engine
  const assessmentCtx = {
    action_type: actionType as import('@mnemom/types').ActionType,
    risk_tolerance: riskTolerance,
    amount: ctx.amount as number | undefined,
  };
  const nowMs = Date.now();
  const result = computeTeamRisk(agents, pairwise, violationsMap, assessmentCtx, nowMs, teamCardData);

  // Generate assessment ID
  const assessmentId = `tra-${crypto.randomUUID().slice(0, 8)}`;
  const n = agentIds.length;

  const teamAssessment = {
    assessment_id: assessmentId,
    team_id: teamId ?? null,
    ...result,
    proof_id: null as string | null,
    proof_status: 'none' as const,
    created_at: new Date().toISOString(),
  };
  const specTeamAssessment = toSpecTeamAssessment(teamAssessment);

  // Insert into team_risk_assessments
  const { error: insertError } = await supabaseInsert(env, 'team_risk_assessments', {
    assessment_id: assessmentId,
    account_id: accountId,
    team_id: teamId ?? null,
    agent_ids: agentIds,
    agent_count: n,
    action_type: actionType,
    context: ctx,
    team_risk_score: result.team_risk_score,
    team_risk_level: result.team_risk_level,
    team_coherence_score: result.team_coherence_score,
    team_recommendation: result.team_recommendation,
    portfolio_risk: result.portfolio_risk,
    coherence_risk: result.coherence_risk,
    concentration_risk: result.concentration_risk,
    weakest_link_risk: result.weakest_link_risk,
    individual_assessments: result.individual_assessments,
    outliers: result.outliers,
    clusters: result.clusters,
    value_divergences: result.value_divergences,
    shapley_values: result.shapley_values,
    synergy_type: result.synergy_type,
    explanation: result.explanation,
    input_snapshot: {
      agents: agents.map(a => ({ agent_id: a.agent_id, reputation: a.reputation })),
      pairwise,
      context: assessmentCtx,
      now_ms: nowMs,
    },
    source,
  });

  if (insertError) {
    console.error('[handleAssessTeamRisk] Insert error:', insertError);
  }

  // Insert metering event (non-blocking, fail-open)
  const meteringEventId = `me-${crypto.randomUUID().slice(0, 8)}`;
  supabaseInsert(env, 'metering_events', {
    event_id: meteringEventId,
    account_id: accountId,
    agent_id: agentIds[0], // primary agent for metering
    event_type: 'risk_assessment_team',
    metadata: { assessment_id: assessmentId, agent_count: n, action_type: actionType },
  }).catch(() => { /* fail-open */ });

  // Fire-and-forget ZK proof if prover is configured
  if (env.PROVER_URL) {
    requestRiskProof(env, assessmentId, 'team_coherence', {
      agents: agents.map(a => ({ agent_id: a.agent_id, reputation: a.reputation })),
      pairwise,
      context: assessmentCtx,
      now_ms: nowMs,
    }).catch(() => { /* fail-open */ });
  }

  return jsonResponse(specTeamAssessment);
}

// ============================================
// 3. GET /v1/risk/assessments/:id
// ============================================

export async function handleGetAssessment(
  assessmentId: string,
  env: RiskEnv,
): Promise<Response> {
  const { data, error } = await supabaseQuery(env, 'risk_assessments', {
    filters: { assessment_id: assessmentId },
    single: true,
  });

  if (error) {
    const { status, message } = classifyPostgrestError(error, 'Assessment not found');
    return errorResponse(message, status);
  }
  if (!data) return errorResponse('Assessment not found', 404);

  return jsonResponse(toSpecAssessment(data as Record<string, unknown>));
}

// ============================================
// 4. GET /v1/risk/history/:agent_id
// ============================================

export async function handleGetHistory(
  agentId: string,
  env: RiskEnv,
  url: URL,
): Promise<Response> {
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') ?? '20', 10)));
  const offset = Math.max(0, parseInt(url.searchParams.get('offset') ?? '0', 10));

  const includePlayground = url.searchParams.get('include_playground') === 'true';
  const { data, error, count } = await supabaseQuery(env, 'risk_assessments', {
    filters: { agent_id: agentId },
    rawFilters: includePlayground ? [] : ['source=neq.playground'],
    order: 'created_at.desc',
    limit,
    offset,
  });

  if (error) {
    const { status, message } = classifyPostgrestError(error);
    return errorResponse(message, status);
  }

  const rows = (data as unknown[]) ?? [];
  return jsonResponse({
    assessments: rows.map((r) => toSpecAssessment(r as Record<string, unknown>)),
    total: count ?? rows.length,
    limit,
    offset,
  });
}

// ============================================
// 5. GET /v1/risk/team-assessments/:id
// ============================================

export async function handleGetTeamAssessment(
  assessmentId: string,
  env: RiskEnv,
): Promise<Response> {
  const { data, error } = await supabaseQuery(env, 'team_risk_assessments', {
    filters: { assessment_id: assessmentId },
    single: true,
  });

  if (error) {
    const { status, message } = classifyPostgrestError(error, 'Team assessment not found');
    return errorResponse(message, status);
  }
  if (!data) return errorResponse('Team assessment not found', 404);

  return jsonResponse(toSpecTeamAssessment(data as Record<string, unknown>));
}

// ============================================
// 6. GET /v1/risk/team-history/:team_id
// ============================================

export async function handleGetTeamHistory(
  teamId: string,
  env: RiskEnv,
  url: URL,
): Promise<Response> {
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get('limit') ?? '20', 10)));
  const offset = Math.max(0, parseInt(url.searchParams.get('offset') ?? '0', 10));

  const { data, error, count } = await supabaseQuery(env, 'team_risk_assessments', {
    filters: { team_id: teamId },
    order: 'created_at.desc',
    limit,
    offset,
  });

  if (error) {
    const { status, message } = classifyPostgrestError(error);
    return errorResponse(message, status);
  }

  const rows = (data as unknown[]) ?? [];
  return jsonResponse({
    team_id: teamId,
    assessments: rows.map((r) => toSpecTeamAssessment(r as Record<string, unknown>)),
    total: count ?? rows.length,
    limit,
    offset,
  });
}

// ============================================
// 7. GET /v1/risk/proofs/:id
// ============================================

export async function handleGetProof(
  proofId: string,
  env: RiskEnv,
): Promise<Response> {
  const { data, error } = await supabaseQuery(env, 'risk_proofs', {
    filters: { proof_id: proofId },
    single: true,
  });

  if (error) {
    const { status, message } = classifyPostgrestError(error, 'Proof not found');
    return errorResponse(message, status);
  }
  if (!data) return errorResponse('Proof not found', 404);

  return jsonResponse(data);
}

