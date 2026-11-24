import type { Scenario } from './types.ts';

// Reproducible rollout scenarios. The fleet is generated from fleetSeed, so each
// scenario is a fixed inventory + a fixed set of injected faults.

export const SCENARIOS: Scenario[] = [
  {
    id: 'clean', title: 'Clean monthly patch cycle', expect: 'completed',
    blurb: 'Patch Tuesday for the whole fleet during the 01:00–05:00 prod window. Canary passes, every wave passes its health gate, rollout completes.',
    fleetSeed: 101, nowHour: 2, faults: [],
  },
  {
    id: 'bad-kernel', title: 'Bad kernel patch caught at canary', expect: 'halted',
    blurb: 'A kernel update wedges a canary host (it never returns healthy after reboot). The gate halts at the canary and that host rolls back — exactly what a canary is for: a bad patch is caught before any prod wave is touched. Halted at wave 0 is a success of the process, not a failure.',
    fleetSeed: 101, nowHour: 2, faults: [{ host: 'web-s01', phase: 'health', reason: 'kernel panic on reboot; host did not return healthy' }],
  },
  {
    id: 'wave-failure', title: 'Regression surfaces in a prod wave', expect: 'halted',
    blurb: 'Canary and staging pass, but two hosts in a prod wave fail their post-patch health check. The gate is breached, the wave auto-rolls-back, and the rollout halts before touching the rest of prod.',
    fleetSeed: 203, nowHour: 2, faults: [
      { host: 'app-p01', phase: 'health', reason: 'httpd failed readiness after patch' },
      { host: 'app-p02', phase: 'reboot', reason: 'did not return from reboot within 10m' },
    ],
  },
  {
    id: 'window', title: 'Mid-day run respects maintenance windows', expect: 'completed',
    blurb: 'The job fires at 14:00. Prod hosts (window 01:00–05:00) are deferred and recorded in the POA&M; only staging (any-time window) patches now.',
    fleetSeed: 101, nowHour: 14, faults: [],
  },
  {
    id: 'kev-emergency', title: 'Emergency KEV remediation', expect: 'completed',
    blurb: 'An out-of-cycle run to close actively-exploited (CISA KEV) CVEs. The planner orders the most severe/KEV hosts into the canary first so the highest-risk boxes are proven and patched soonest.',
    fleetSeed: 307, nowHour: 2, faults: [],
  },
];
