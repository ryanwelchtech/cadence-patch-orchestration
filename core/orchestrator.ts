import type { Fault, Fleet, Host, HostResult, PoamItem, RolloutPlan, RolloutResult, WaveResult } from './types.ts';

// STIG remediation model: each applied update closes a fraction of the open
// OpenSCAP findings for its package class; a fully patched host lands near the
// hardened baseline. Deterministic, no randomness here.
const STIG_GAIN_PER_SEVERITY = { critical: 0.06, high: 0.04, medium: 0.025, low: 0.015 };

export function stigAfter(h: Host): number {
  const gain = h.updates.reduce((a, u) => a + STIG_GAIN_PER_SEVERITY[u.severity], 0);
  return Math.min(0.99, h.stigBefore + gain);
}

export interface RunOptions {
  faults: Fault[];
  /** called after each host transitions, for the live console */
  onHost?: (r: HostResult) => void | Promise<void>;
  onWave?: (w: WaveResult) => void | Promise<void>;
  stepDelayMs?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function patchHost(h: Host, wave: number, faults: Fault[], onHost?: RunOptions['onHost'], delay = 0): Promise<HostResult> {
  const fault = faults.find((f) => f.host === h.name);
  const base: HostResult = { host: h.name, state: 'patching', wave, patched: [], rebooted: false, stigBefore: h.stigBefore, stigAfter: h.stigBefore };
  await onHost?.({ ...base });
  if (delay) await sleep(delay);

  if (fault?.phase === 'patch') {
    const r = { ...base, state: 'failed' as const, failReason: fault.reason };
    await onHost?.(r); return r;
  }
  base.patched = h.updates;

  const needsReboot = h.updates.some((u) => u.rebootRequired);
  if (needsReboot) {
    const r1 = { ...base, state: 'rebooting' as const };
    await onHost?.(r1); if (delay) await sleep(delay);
    if (fault?.phase === 'reboot') { const r = { ...base, state: 'failed' as const, rebooted: false, failReason: fault.reason }; await onHost?.(r); return r; }
    base.rebooted = true;
  }

  if (fault?.phase === 'health') { const r = { ...base, state: 'failed' as const, failReason: fault.reason }; await onHost?.(r); return r; }

  const done: HostResult = { ...base, state: 'healthy', stigAfter: stigAfter(h) };
  await onHost?.(done);
  return done;
}

export async function run(fleet: Fleet, plan: RolloutPlan, opts: RunOptions): Promise<RolloutResult> {
  const byName = new Map(fleet.hosts.map((h) => [h.name, h]));
  const waveResults: WaveResult[] = [];
  let halted = false;
  let haltedAtWave: number | undefined;

  for (const wave of plan.waves) {
    const results: HostResult[] = [];
    // hosts in a wave patch concurrently (Ansible `serial` = wave size)
    const hostObjs = wave.hosts.map((n) => byName.get(n)!);
    const settled = await Promise.all(hostObjs.map((h) => patchHost(h, wave.index, opts.faults, opts.onHost, opts.stepDelayMs ?? 0)));
    results.push(...settled);

    const failed = results.filter((r) => r.state === 'failed').length;
    const gate = plan.gate;
    const breached = failed > gate.maxFailCount || failed / Math.max(1, wave.hosts.length) > gate.maxFailFraction;

    const rolledBack: string[] = [];
    if (breached) {
      // automatic rollback: every host patched in THIS wave is reverted to its
      // pre-patch snapshot (the Ansible rollback play restores the boot entry /
      // package set). Successful hosts in prior waves are left in place.
      for (const r of results) {
        if (r.state === 'healthy' || r.state === 'failed') {
          r.state = 'rolledback'; r.rolledBack = true; r.patched = []; r.rebooted = false; r.stigAfter = r.stigBefore;
          rolledBack.push(r.host);
          await opts.onHost?.({ ...r });
        }
      }
    }

    const wr: WaveResult = { wave, results, failed, gateBreached: breached, rolledBack };
    waveResults.push(wr);
    await opts.onWave?.(wr);
    if (breached) { halted = true; haltedAtWave = wave.index; break; }
  }

  const all = waveResults.flatMap((w) => w.results);
  const healthy = all.filter((r) => r.state === 'healthy');
  let cvesClosed = 0, kevClosed = 0;
  for (const r of healthy) for (const u of r.patched) { if (u.cve) cvesClosed++; if (u.kev) kevClosed++; }
  const patchedNames = new Set(healthy.map((r) => r.host));
  const before = fleet.hosts.reduce((a, h) => a + h.stigBefore, 0) / fleet.hosts.length;
  const after = fleet.hosts.reduce((a, h) => a + (patchedNames.has(h.name) ? stigAfter(h) : h.stigBefore), 0) / fleet.hosts.length;

  return {
    fleet: fleet.name, waves: waveResults,
    status: halted ? 'halted' : 'completed', haltedAtWave,
    patchedHosts: healthy.length,
    failedHosts: all.filter((r) => r.rolledBack || r.state === 'failed').length,
    rolledBackHosts: all.filter((r) => r.rolledBack).length,
    skipped: plan.skipped,
    cvesClosed, kevClosed,
    stigBeforeMean: before, stigAfterMean: after,
  };
}

/** POA&M: what the cycle remediated and what remains open (for the ISSM/auditor). */
export function poam(fleet: Fleet, result: RolloutResult): PoamItem[] {
  const patched = new Set(result.waves.flatMap((w) => w.results).filter((r) => r.state === 'healthy').map((r) => r.host));
  const skippedReason = new Map(result.skipped.map((s) => [s.host, s.reason]));
  const items: PoamItem[] = [];
  for (const h of fleet.hosts) {
    for (const u of h.updates) {
      if (!u.cve) continue;
      const remediated = patched.has(h.name);
      items.push({
        host: h.name, cve: u.cve, pkg: u.pkg, severity: u.severity, kev: !!u.kev,
        status: remediated ? 'remediated' : skippedReason.has(h.name) ? 'deferred' : 'open',
        reason: remediated ? undefined : skippedReason.get(h.name) ?? 'rollout halted before this host',
      });
    }
  }
  return items;
}
