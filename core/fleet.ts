import type { Fleet, Host, Role, Update } from './types.ts';

// Deterministic fleet generator (seeded LCG) so a scenario id always yields the
// same inventory — reproducibility is a change-control requirement.
export class Rng {
  private s: number;
  constructor(seed: number) { this.s = (seed >>> 0) || 1; }
  next(): number { this.s = (this.s * 1103515245 + 12345) & 0x7fffffff; return this.s / 0x7fffffff; }
  int(n: number): number { return Math.floor(this.next() * n); }
  pick<T>(a: T[]): T { return a[this.int(a.length)]; }
}

const CATALOG: Omit<Update, 'from' | 'to'>[] = [
  { pkg: 'kernel', cve: 'CVE-2024-1086', kev: true, severity: 'critical', rebootRequired: true },
  { pkg: 'openssl', cve: 'CVE-2024-6119', kev: false, severity: 'high', rebootRequired: false },
  { pkg: 'glibc', cve: 'CVE-2024-2961', kev: false, severity: 'high', rebootRequired: true },
  { pkg: 'sudo', cve: 'CVE-2023-22809', kev: true, severity: 'high', rebootRequired: false },
  { pkg: 'bind-utils', cve: 'CVE-2024-1737', kev: false, severity: 'medium', rebootRequired: false },
  { pkg: 'curl', cve: 'CVE-2024-7264', kev: false, severity: 'medium', rebootRequired: false },
  { pkg: 'python3', cve: 'CVE-2024-6232', kev: false, severity: 'medium', rebootRequired: false },
  { pkg: 'httpd', cve: 'CVE-2024-38476', kev: false, severity: 'high', rebootRequired: false },
];

const ver = (r: Rng) => `${r.int(3) + 1}.${r.int(9)}.${r.int(9)}-${r.int(40) + 1}.el9`;

const ROLE_MIX: { role: Role; count: number }[] = [
  { role: 'web', count: 8 }, { role: 'app', count: 8 }, { role: 'db', count: 6 }, { role: 'cache', count: 2 },
];

export function makeFleet(seed: number, nowHour: number, name = 'enclave-rhel9'): Fleet {
  const r = new Rng(seed);
  const hosts: Host[] = [];
  const azs = ['a', 'b', 'c'] as const;
  for (const { role, count } of ROLE_MIX) {
    const stagingCount = Math.ceil(count * 0.25);
    const idx = { staging: 0, prod: 0 };
    for (let i = 0; i < count; i++) {
      const env = i < stagingCount ? 'staging' : 'prod';
      const n = ++idx[env];
      const nUpdates = 2 + r.int(4);
      const chosen = new Set<number>();
      while (chosen.size < nUpdates) chosen.add(r.int(CATALOG.length));
      const updates: Update[] = [...chosen].map((ci) => ({ ...CATALOG[ci], from: ver(r), to: ver(r) }));
      hosts.push({
        name: `${role}-${env.slice(0, 1)}${String(n).padStart(2, '0')}`,
        env, role, az: azs[(hosts.length + i) % 3],
        updates,
        stigBefore: 0.72 + r.next() * 0.16, // 72–88% before patch cycle
        window: env === 'prod' ? [1, 5] : [0, 24], // prod patches 01:00–05:00; staging anytime
        frozen: false,
      });
    }
  }
  return { name, hosts, nowHour };
}

export function fleetStats(f: Fleet) {
  const cves = new Set<string>();
  let kev = 0;
  for (const h of f.hosts) for (const u of h.updates) { if (u.cve) cves.add(u.cve + h.name); if (u.kev) kev++; }
  return {
    hosts: f.hosts.length,
    openUpdates: f.hosts.reduce((a, h) => a + h.updates.length, 0),
    kevUpdates: kev,
    meanStig: f.hosts.reduce((a, h) => a + h.stigBefore, 0) / f.hosts.length,
  };
}
