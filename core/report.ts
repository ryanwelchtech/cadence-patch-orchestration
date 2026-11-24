// Change-record / CI report for a rollout scenario. `npm run report -- <id>`.

import { makeFleet } from './fleet.ts';
import { plan } from './planner.ts';
import { poam, run } from './orchestrator.ts';
import { SCENARIOS } from './scenarios.ts';

const id = process.argv[2] ?? 'clean';
const json = process.argv.includes('--json');
const s = SCENARIOS.find((x) => x.id === id);
if (!s) { console.error(`unknown scenario "${id}". options: ${SCENARIOS.map((x) => x.id).join(', ')}`); process.exit(64); }

const fleet = makeFleet(s.fleetSeed, s.nowHour);
const p = plan(fleet);
const result = await run(fleet, p, { faults: s.faults });
const items = poam(fleet, result);
const pct = (n: number) => `${(n * 100).toFixed(1)}%`;

if (json) {
  console.log(JSON.stringify({ scenario: s.id, status: result.status, haltedAtWave: result.haltedAtWave, patched: result.patchedHosts, rolledBack: result.rolledBackHosts, cvesClosed: result.cvesClosed, kevClosed: result.kevClosed, stigBefore: result.stigBeforeMean, stigAfter: result.stigAfterMean, waves: p.waves.length }, null, 2));
} else {
  console.log(`\nCADENCE rollout — ${s.title}\n${'='.repeat(58)}`);
  console.log(`fleet            ${fleet.name}  (${fleet.hosts.length} hosts, run at ${String(fleet.nowHour).padStart(2, '0')}:00)`);
  console.log(`plan             ${p.waves.length} waves (canary ${p.waves[0]?.hosts.length ?? 0}), blast cap ${pct(p.maxRoleFraction)}/role, gate ≤${p.gate.maxFailCount} fail`);
  console.log(`status           ${result.status.toUpperCase()}${result.haltedAtWave !== undefined ? ` at wave ${result.haltedAtWave}` : ''}`);
  console.log(`patched          ${result.patchedHosts}   rolled back ${result.rolledBackHosts}   deferred/skipped ${result.skipped.length}`);
  console.log(`CVEs closed      ${result.cvesClosed}   (KEV ${result.kevClosed})`);
  console.log(`STIG mean        ${pct(result.stigBeforeMean)} → ${pct(result.stigAfterMean)}`);
  console.log('\nwaves');
  for (const w of result.waves) {
    const tag = w.gateBreached ? `GATE BREACHED → rolled back ${w.rolledBack.length}` : 'ok';
    console.log(`  ${w.wave.kind === 'canary' ? 'canary' : `wave ${w.wave.index}`.padEnd(7)} [${w.wave.hosts.join(', ')}]  ${w.failed ? `${w.failed} failed · ` : ''}${tag}`);
  }
  const open = items.filter((i) => i.status !== 'remediated');
  console.log(`\nPOA&M: ${items.filter((i) => i.status === 'remediated').length} remediated, ${open.length} open/deferred`);
  for (const i of open.filter((x) => x.kev).slice(0, 6)) console.log(`  OPEN  ${i.host}  ${i.cve} ${i.pkg} [${i.severity}${i.kev ? ' KEV' : ''}]  ${i.reason}`);
}
