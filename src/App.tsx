import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Host, HostResult, HostState, RolloutResult, Scenario, WaveResult } from '../core/types.ts';
import { makeFleet } from '../core/fleet.ts';
import { plan } from '../core/planner.ts';
import { poam, run } from '../core/orchestrator.ts';
import { SCENARIOS } from '../core/scenarios.ts';

const auto = new URLSearchParams(location.search).has('auto');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const STATE_LABEL: Record<HostState, string> = { pending: '·', patching: '▼', rebooting: '↻', healthy: '✓', failed: '✗', rolledback: '⤺', skipped: '—' };

export function App() {
  const [scenarioId, setScenarioId] = useState(SCENARIOS[0].id);
  const scenario = useMemo<Scenario>(() => SCENARIOS.find((s) => s.id === scenarioId)!, [scenarioId]);
  const fleet = useMemo(() => makeFleet(scenario.fleetSeed, scenario.nowHour), [scenario]);
  const thePlan = useMemo(() => plan(fleet), [fleet]);
  const [states, setStates] = useState<Map<string, HostState>>(new Map());
  const [curWave, setCurWave] = useState(-1);
  const [waveResults, setWaveResults] = useState<WaveResult[]>([]);
  const [result, setResult] = useState<RolloutResult | null>(null);
  const [running, setRunning] = useState(false);
  const cancel = useRef(false);
  const hostByName = useMemo(() => new Map(fleet.hosts.map((h) => [h.name, h])), [fleet]);

  const reset = useCallback(() => {
    const m = new Map<string, HostState>();
    for (const h of fleet.hosts) m.set(h.name, 'pending');
    for (const s of thePlan.skipped) m.set(s.host, 'skipped');
    setStates(m); setCurWave(-1); setWaveResults([]); setResult(null);
  }, [fleet, thePlan]);

  useEffect(() => { reset(); }, [reset]);

  // Compute everything from the id passed in, so the run never depends on stale
  // closed-over state (the live button passes the selected id; the auto
  // walkthrough passes each scenario in turn).
  const runId = useCallback(async (id: string) => {
    const s = SCENARIOS.find((x) => x.id === id)!;
    const f = makeFleet(s.fleetSeed, s.nowHour);
    const p = plan(f);
    cancel.current = true; await sleep(10); cancel.current = false;
    // seed the grid for THIS scenario's plan
    const init = new Map<string, HostState>();
    for (const h of f.hosts) init.set(h.name, 'pending');
    for (const sk of p.skipped) init.set(sk.host, 'skipped');
    setStates(init); setCurWave(-1); setWaveResults([]); setResult(null); setRunning(true);
    await sleep(120);
    const res = await run(f, p, {
      faults: s.faults,
      stepDelayMs: auto ? 150 : 240,
      onHost: async (r: HostResult) => { if (!cancel.current) setStates((m) => { const n = new Map(m); n.set(r.host, r.state); return n; }); },
      onWave: async (w: WaveResult) => { if (cancel.current) return; setCurWave(w.wave.index); setWaveResults((prev) => [...prev, w]); await sleep(auto ? 300 : 500); },
    });
    if (cancel.current) return;
    setResult(res); setRunning(false);
  }, []);

  const start = useCallback(() => runId(scenarioId), [runId, scenarioId]);

  useEffect(() => {
    if (!auto) return;
    (async () => {
      for (const id of ['clean', 'wave-failure', 'window']) { setScenarioId(id); await sleep(500); await runId(id); await sleep(1700); }
      (window as unknown as { __done: boolean }).__done = true;
    })();
  }, [runId]); // eslint-disable-line react-hooks/exhaustive-deps

  const roles: Host['role'][] = ['web', 'app', 'db', 'cache'];
  const stig = result ? { before: result.stigBeforeMean, after: result.stigAfterMean } : { before: fleet.hosts.reduce((a, h) => a + h.stigBefore, 0) / fleet.hosts.length, after: 0 };
  const poamItems = result ? poam(fleet, result) : [];
  const kevOpen = poamItems.filter((i) => i.kev && i.status !== 'remediated');

  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="logo">⟲</span>
          <div><h1>CADENCE</h1><p>Patch-wave orchestration for RHEL fleets · canary → waves → health-gated rollback</p></div>
        </div>
        <div className="chips">
          <span className="chip">fleet <b>{fleet.hosts.length}</b></span>
          <span className="chip">run @ <b>{String(fleet.nowHour).padStart(2, '0')}:00</b></span>
          <span className="chip">waves <b>{thePlan.waves.length}</b></span>
          <span className="chip">blast cap <b>{Math.round(thePlan.maxRoleFraction * 100)}%</b>/role</span>
          <span className="chip">gate <b>≤{thePlan.gate.maxFailCount} fail</b></span>
        </div>
      </header>

      <main>
        <aside className="panel scn">
          <h2>Rollout scenarios</h2>
          {SCENARIOS.map((s) => (
            <button key={s.id} className={`row ${scenarioId === s.id ? 'active' : ''}`} disabled={running} onClick={() => setScenarioId(s.id)}>
              <span className={`dot ${s.expect}`} /><span>{s.title}</span>
            </button>
          ))}
          <p className="blurb">{scenario.blurb}</p>
          <button className="go" onClick={start} disabled={running}>{running ? 'rolling out…' : '▶ Run rollout'}</button>
        </aside>

        <section className="panel center">
          <div className="gridhead">
            <h2>Fleet — {fleet.name}</h2>
            <div className="legend">
              <span><i className="st pending" />pending</span>
              <span><i className="st patching" />patching</span>
              <span><i className="st healthy" />healthy</span>
              <span><i className="st rolledback" />rolled back</span>
              <span><i className="st skipped" />deferred</span>
            </div>
          </div>
          <div className="fleet">
            {roles.map((role) => (
              <div key={role} className="rolecol">
                <div className="rolelabel">{role}</div>
                {fleet.hosts.filter((h) => h.role === role).map((h) => {
                  const st = states.get(h.name) ?? 'pending';
                  const w = thePlan.waves.find((wv) => wv.hosts.includes(h.name));
                  return (
                    <div key={h.name} className={`host ${st} ${w?.kind === 'canary' ? 'canary' : ''} ${curWave >= 0 && w?.index === curWave ? 'current' : ''}`} title={`${h.name} · AZ ${h.az} · ${h.env} · ${h.updates.length} updates · wave ${w ? w.index : 'skip'}`}>
                      <span className="hn">{h.name}</span>
                      <span className="hs">{STATE_LABEL[st]}</span>
                      {h.updates.some((u) => u.kev) && <span className="kev">KEV</span>}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          <div className="wavebar">
            {thePlan.waves.map((w) => {
              const wr = waveResults.find((x) => x.wave.index === w.index);
              const cls = wr ? (wr.gateBreached ? 'breach' : 'ok') : curWave === w.index ? 'active' : 'idle';
              return <div key={w.index} className={`wtick ${cls}`}>{w.kind === 'canary' ? 'canary' : `W${w.index}`}{wr?.gateBreached && ' ⟲'}</div>;
            })}
          </div>
        </section>

        <section className="panel right">
          <h2>Rollout status</h2>
          {result ? (
            <div className={`statusbox ${result.status}`}>
              <b>{result.status === 'completed' ? 'COMPLETED' : `HALTED @ wave ${result.haltedAtWave}`}</b>
              <span>{result.status === 'completed' ? 'All eligible hosts patched and healthy.' : result.haltedAtWave === 0 ? 'Bad patch caught at the canary — no prod wave touched. Working as designed.' : 'Health gate breached in a prod wave; that wave auto-rolled-back and the rollout stopped.'}</span>
            </div>
          ) : <div className="statusbox idle"><b>{running ? 'RUNNING' : 'READY'}</b><span>{running ? 'patching current wave…' : 'press Run rollout'}</span></div>}

          <div className="stiggauge">
            <div className="glabel">DISA STIG compliance (fleet mean)</div>
            <div className="bar"><div className="fill before" style={{ width: `${stig.before * 100}%` }} /></div>
            <div className="brow"><span>before</span><b>{(stig.before * 100).toFixed(1)}%</b></div>
            {result && <>
              <div className="bar"><div className="fill after" style={{ width: `${stig.after * 100}%` }} /></div>
              <div className="brow"><span>after</span><b className="g">{(stig.after * 100).toFixed(1)}%</b></div>
            </>}
          </div>

          {result && (
            <div className="metrics">
              <div><b>{result.patchedHosts}</b><span>patched</span></div>
              <div><b className={result.rolledBackHosts ? 'r' : ''}>{result.rolledBackHosts}</b><span>rolled back</span></div>
              <div><b>{result.cvesClosed}</b><span>CVEs closed</span></div>
              <div><b className="k">{result.kevClosed}</b><span>KEV closed</span></div>
            </div>
          )}

          {result && (
            <div className="poam">
              <div className="ph">POA&M · open KEV items <span>{kevOpen.length}</span></div>
              <div className="plist">
                {kevOpen.slice(0, 7).map((i, k) => (
                  <div key={k} className="pi"><b>{i.host}</b><span className="cve">{i.cve}</span><span className="pk">{i.pkg}</span><span className="rsn">{i.reason}</span></div>
                ))}
                {!kevOpen.length && <div className="clean">No open KEV items — all actively-exploited CVEs remediated.</div>}
              </div>
            </div>
          )}
        </section>
      </main>
      <footer>Same deterministic orchestration engine as <code>core/</code> and the CI report (<code>npm run report</code>); <code>ansible/</code> is the executor (serial waves, <code>max_fail_percentage</code> gate, block/rescue rollback, OpenSCAP). Fictitious fleet.</footer>
    </div>
  );
}
