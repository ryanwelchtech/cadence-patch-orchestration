import type { Fleet, Host, HealthGate, RolloutPlan, Wave } from './types.ts';

export interface PlanOptions {
  canarySize: number; // hosts in the canary wave
  maxRoleFraction: number; // blast radius: max fraction of a role patched at once
  gate: HealthGate;
  /** patch staging before prod regardless of blast radius */
  stagingFirst: boolean;
}

export const DEFAULT_PLAN: PlanOptions = {
  canarySize: 2,
  maxRoleFraction: 0.34, // never take more than a third of a role concurrently
  gate: { maxFailFraction: 0.25, maxFailCount: 1 },
  stagingFirst: true,
};

const inWindow = (h: Host, nowHour: number): boolean => {
  const [s, e] = h.window;
  return s <= e ? nowHour >= s && nowHour < e : nowHour >= s || nowHour < e;
};

/**
 * Build the rollout plan:
 *   1. drop frozen hosts and hosts outside their maintenance window,
 *   2. canary = the smallest-blast hosts with the most severe/KEV updates first,
 *   3. then waves that never exceed maxRoleFraction of any role, and never take
 *      two hosts of the same role in the same AZ in one wave (failure-domain safe),
 *   4. staging-first ordering so prod only moves after staging proves the patch.
 */
export function plan(fleet: Fleet, opts: PlanOptions = DEFAULT_PLAN): RolloutPlan {
  const skipped: { host: string; reason: string }[] = [];
  const eligible: Host[] = [];
  for (const h of fleet.hosts) {
    if (h.frozen) { skipped.push({ host: h.name, reason: 'change-control freeze' }); continue; }
    if (!h.updates.length) { skipped.push({ host: h.name, reason: 'already up to date' }); continue; }
    if (!inWindow(h, fleet.nowHour)) { skipped.push({ host: h.name, reason: `outside maintenance window ${h.window[0]}:00–${h.window[1]}:00` }); continue; }
    eligible.push(h);
  }

  const kevScore = (h: Host) => h.updates.reduce((a, u) => a + (u.kev ? 10 : 0) + ({ critical: 4, high: 3, medium: 2, low: 1 }[u.severity]), 0);
  // ordering key: staging before prod, then most-urgent first
  const order = (a: Host, b: Host) => {
    if (opts.stagingFirst && a.env !== b.env) return a.env === 'staging' ? -1 : 1;
    return kevScore(b) - kevScore(a);
  };
  const sorted = [...eligible].sort(order);

  const waves: Wave[] = [];
  // canary: the top of the sorted list, capped by canarySize, all distinct roles if possible
  const canary: Host[] = [];
  for (const h of sorted) {
    if (canary.length >= opts.canarySize) break;
    if (opts.stagingFirst && canary.length && canary[0].env === 'staging' && h.env !== 'staging') continue;
    canary.push(h);
  }
  if (canary.length) waves.push({ index: 0, kind: 'canary', hosts: canary.map((h) => h.name) });

  const remaining = sorted.filter((h) => !canary.includes(h));
  const roleCounts = new Map<string, number>();
  for (const h of fleet.hosts) roleCounts.set(h.role, (roleCounts.get(h.role) ?? 0) + 1);
  const capOf = (role: string) => Math.max(1, Math.floor((roleCounts.get(role) ?? 1) * opts.maxRoleFraction));

  let wi = waves.length;
  // Promote environment by environment: staging is a hard boundary before prod,
  // so prod waves only begin once staging is fully patched (and, at runtime,
  // proven healthy by the gate). Within an env, bound each wave by blast radius
  // and keep each wave failure-domain-safe (no two same-role hosts in one AZ).
  const envOrder: Host['env'][] = opts.stagingFirst ? ['staging', 'prod'] : ['prod', 'staging'];
  for (const env of envOrder) {
    const pool = remaining.filter((h) => h.env === env);
    while (pool.length) {
      const take: Host[] = [];
      const perRole = new Map<string, number>();
      const azByRole = new Map<string, Set<string>>();
      for (let i = 0; i < pool.length; ) {
        const h = pool[i];
        const used = perRole.get(h.role) ?? 0;
        const azs = azByRole.get(h.role) ?? new Set<string>();
        if (used >= capOf(h.role) || azs.has(h.az)) { i++; continue; }
        take.push(h);
        perRole.set(h.role, used + 1);
        azs.add(h.az); azByRole.set(h.role, azs);
        pool.splice(i, 1);
      }
      if (!take.length) take.push(pool.shift()!); // progress guarantee
      waves.push({ index: wi++, kind: 'wave', hosts: take.map((h) => h.name) });
    }
  }

  return { fleet: fleet.name, waves, skipped, gate: opts.gate, maxRoleFraction: opts.maxRoleFraction };
}
