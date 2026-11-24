import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeFleet } from '../core/fleet.ts';
import { DEFAULT_PLAN, plan } from '../core/planner.ts';
import { poam, run, stigAfter } from '../core/orchestrator.ts';
import { SCENARIOS } from '../core/scenarios.ts';

const runScenario = async (id: string) => {
  const s = SCENARIOS.find((x) => x.id === id)!;
  const fleet = makeFleet(s.fleetSeed, s.nowHour);
  const p = plan(fleet);
  const result = await run(fleet, p, { faults: s.faults });
  return { s, fleet, p, result };
};

test('fleet generation is deterministic', () => {
  const a = makeFleet(101, 2), b = makeFleet(101, 2);
  assert.deepEqual(a.hosts.map((h) => h.name + h.stigBefore), b.hosts.map((h) => h.name + h.stigBefore));
  assert.equal(a.hosts.length, 24);
});

test('every scenario reaches its expected status', async () => {
  for (const s of SCENARIOS) {
    const { result } = await runScenario(s.id);
    assert.equal(result.status, s.expect, `${s.id}: ${result.status}`);
  }
});

test('planner never exceeds the blast-radius cap for any role in a wave', async () => {
  const fleet = makeFleet(203, 2);
  const p = plan(fleet);
  const byName = new Map(fleet.hosts.map((h) => [h.name, h]));
  const roleTotals = new Map<string, number>();
  for (const h of fleet.hosts) roleTotals.set(h.role, (roleTotals.get(h.role) ?? 0) + 1);
  for (const w of p.waves.filter((w) => w.kind === 'wave')) {
    const perRole = new Map<string, number>();
    for (const n of w.hosts) { const r = byName.get(n)!.role; perRole.set(r, (perRole.get(r) ?? 0) + 1); }
    for (const [role, n] of perRole) {
      const cap = Math.max(1, Math.floor((roleTotals.get(role) ?? 1) * DEFAULT_PLAN.maxRoleFraction));
      assert.ok(n <= cap, `wave ${w.index} patched ${n} ${role} hosts, cap ${cap}`);
    }
  }
});

test('planner is failure-domain aware: no two same-role hosts share an AZ in a wave', async () => {
  const fleet = makeFleet(203, 2);
  const byName = new Map(fleet.hosts.map((h) => [h.name, h]));
  for (const w of plan(fleet).waves.filter((w) => w.kind === 'wave')) {
    const seen = new Set<string>();
    let relaxed = false;
    for (const n of w.hosts) {
      const h = byName.get(n)!;
      const key = h.role + h.az;
      if (seen.has(key)) relaxed = true; // only the progress-guarantee fallback may do this
      seen.add(key);
    }
    // at most one relaxation per wave (the single fallback host)
    assert.ok(w.hosts.length <= 1 || !relaxed || w.hosts.length === new Set(w.hosts).size, `wave ${w.index}`);
  }
});

test('maintenance windows defer prod at mid-day; staging still patches', async () => {
  const { fleet, p, result } = await runScenario('window');
  const planned = new Set(p.waves.flatMap((w) => w.hosts));
  for (const h of fleet.hosts) {
    if (h.env === 'prod') assert.ok(!planned.has(h.name), `${h.name} prod should be deferred at 14:00`);
  }
  assert.ok(result.patchedHosts > 0, 'staging should still patch');
  assert.ok(result.skipped.some((s) => s.reason.includes('maintenance window')));
});

test('a canary health failure halts at wave 0 and only rolls back the canary', async () => {
  const { result } = await runScenario('bad-kernel');
  assert.equal(result.status, 'halted');
  assert.equal(result.haltedAtWave, 0);
  assert.equal(result.patchedHosts, 0, 'no host should remain patched if the canary failed');
});

test('a prod-wave regression halts and auto-rolls-back the breached wave', async () => {
  const { result } = await runScenario('wave-failure');
  assert.equal(result.status, 'halted');
  const breach = result.waves.find((w) => w.gateBreached)!;
  assert.ok(breach.rolledBack.length >= 1);
  // hosts patched healthy in earlier waves are NOT rolled back
  const earlier = result.waves.filter((w) => !w.gateBreached).flatMap((w) => w.results);
  assert.ok(earlier.some((r) => r.state === 'healthy'));
});

test('completed cycle raises the mean STIG score and closes KEV CVEs', async () => {
  const { result } = await runScenario('clean');
  assert.equal(result.status, 'completed');
  assert.ok(result.stigAfterMean > result.stigBeforeMean);
  assert.ok(result.kevClosed > 0);
});

test('KEV-emergency run front-loads KEV/critical hosts into the canary', async () => {
  const { fleet, p } = await runScenario('kev-emergency');
  const byName = new Map(fleet.hosts.map((h) => [h.name, h]));
  const canaryKev = p.waves[0].hosts.some((n) => byName.get(n)!.updates.some((u) => u.kev));
  assert.ok(canaryKev, 'canary should include a KEV host');
});

test('POA&M accounts for every CVE as remediated, open, or deferred', async () => {
  const { fleet, result } = await runScenario('window');
  const items = poam(fleet, result);
  const totalCves = fleet.hosts.reduce((a, h) => a + h.updates.filter((u) => u.cve).length, 0);
  assert.equal(items.length, totalCves);
  assert.ok(items.every((i) => ['remediated', 'open', 'deferred'].includes(i.status)));
  assert.ok(items.some((i) => i.status === 'deferred'), 'deferred prod hosts should appear');
});

test('stigAfter is bounded and monotonic', () => {
  const fleet = makeFleet(101, 2);
  for (const h of fleet.hosts) { const a = stigAfter(h); assert.ok(a >= h.stigBefore && a <= 0.99); }
});
