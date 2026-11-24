// CADENCE — patch-wave orchestration for RHEL fleets.
//
// The orchestrator decides *how* a patch cycle rolls out: a canary first, then
// blast-radius-bounded waves, each gated on post-patch health, with automatic
// rollback when a wave fails. Ansible is the executor (ansible/); this engine is
// the brain, and it is deterministic so the same fleet + seed always produces
// the same plan and the same result — which is what makes it testable and what
// makes a change-advisory-board review meaningful.

export type Env = 'prod' | 'staging';
export type Role = 'web' | 'app' | 'db' | 'cache';
export type HostState = 'pending' | 'patching' | 'rebooting' | 'healthy' | 'failed' | 'rolledback' | 'skipped';

export interface Update {
  pkg: string;
  from: string;
  to: string;
  cve?: string;
  kev?: boolean; // CISA Known Exploited Vulnerability
  severity: 'low' | 'medium' | 'high' | 'critical';
  rebootRequired: boolean;
}

export interface Host {
  name: string;
  env: Env;
  role: Role;
  /** availability-zone / failure domain; waves never take a whole AZ of a role */
  az: 'a' | 'b' | 'c';
  updates: Update[];
  /** DISA STIG / OpenSCAP pass ratio before patching, 0..1 */
  stigBefore: number;
  /** maintenance window in 24h local hours [start, end); patching only inside it */
  window: [number, number];
  /** marks a host that must not be auto-patched (frozen / under change-control hold) */
  frozen?: boolean;
}

export interface Fleet {
  name: string;
  hosts: Host[];
  /** current wall-clock hour used to evaluate maintenance windows (0..23) */
  nowHour: number;
}

export interface Wave {
  index: number;
  kind: 'canary' | 'wave';
  hosts: string[];
}

export interface HealthGate {
  /** fraction of a wave allowed to fail before the whole rollout halts */
  maxFailFraction: number;
  /** absolute number of failures allowed before halt (whichever is stricter) */
  maxFailCount: number;
}

export interface RolloutPlan {
  fleet: string;
  waves: Wave[];
  skipped: { host: string; reason: string }[];
  gate: HealthGate;
  /** blast-radius cap: max fraction of a role patched concurrently */
  maxRoleFraction: number;
}

export interface HostResult {
  host: string;
  state: HostState;
  wave: number;
  patched: Update[];
  rebooted: boolean;
  stigBefore: number;
  stigAfter: number;
  failReason?: string;
  rolledBack?: boolean;
}

export interface WaveResult {
  wave: Wave;
  results: HostResult[];
  failed: number;
  gateBreached: boolean;
  rolledBack: string[];
}

export interface RolloutResult {
  fleet: string;
  waves: WaveResult[];
  status: 'completed' | 'halted';
  haltedAtWave?: number;
  patchedHosts: number;
  failedHosts: number;
  rolledBackHosts: number;
  skipped: { host: string; reason: string }[];
  /** CVEs closed across the fleet (patched hosts only) */
  cvesClosed: number;
  kevClosed: number;
  stigBeforeMean: number;
  stigAfterMean: number;
}

/** A deterministic per-host patch outcome, so scenarios are reproducible. */
export interface Fault {
  host: string;
  /** which phase breaks */
  phase: 'patch' | 'reboot' | 'health';
  reason: string;
}

export interface Scenario {
  id: string;
  title: string;
  blurb: string;
  fleetSeed: number;
  nowHour: number;
  faults: Fault[];
  expect: 'completed' | 'halted';
}

export interface PoamItem {
  host: string;
  cve: string;
  pkg: string;
  severity: Update['severity'];
  kev: boolean;
  status: 'remediated' | 'open' | 'deferred';
  reason?: string;
}
