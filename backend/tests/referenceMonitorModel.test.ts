// Бонус задания: проверка формальной модели formal/ReferenceMonitor.tla
// полным перебором достижимых состояний (тот же переход Next и те же инварианты),
// плюс сверка правила модели с реальной функцией canRead() из accessControl.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canRead, Level, MAX_FAILURES } from '../src/security/accessControl.ts';

const IPS = ['ip1', 'ip2'] as const;
const LEVELS = [0, 1, 2, 3] as const;
const ANON = 0;
const ADMIN = 2;
const BOUND = 8;

type Outcome = 'none' | 'granted' | 'denied' | 'unauthorized' | 'locked';
interface State {
    failures: number[];
    locked: boolean[];
    last: { outcome: Outcome; clearance: number; level: number; wasLocked: boolean };
    auditFailures: number;
    realFailures: number;
    auditDenied: number;
    realDenied: number;
}

const key = (s: State) => JSON.stringify(s);
const clone = (s: State): State => JSON.parse(JSON.stringify(s));

function mediate(s: State, ip: number, clearance: number, lvl: number): State {
    const n = clone(s);
    if (clearance >= lvl) {
        n.last = { outcome: 'granted', clearance, level: lvl, wasLocked: s.locked[ip] };
    } else {
        n.last = { outcome: 'denied', clearance, level: lvl, wasLocked: s.locked[ip] };
        n.auditDenied++;
        n.realDenied++;
    }
    return n;
}

function next(s: State): State[] {
    const out: State[] = [];
    IPS.forEach((_, ip) => {
        for (const lvl of LEVELS) {
            out.push(mediate(s, ip, ANON, lvl)); // AnonymousRequest
            for (const ok of [true, false]) {     // AuthRequest
                if (s.locked[ip]) {
                    const n = clone(s);
                    n.last = { outcome: 'locked', clearance: 0, level: lvl, wasLocked: true };
                    out.push(n);
                } else if (ok) {
                    const n = mediate(s, ip, ADMIN, lvl);
                    n.failures[ip] = 0;
                    out.push(n);
                } else {
                    const n = clone(s);
                    n.failures[ip] = s.failures[ip] + 1;
                    n.locked[ip] = s.failures[ip] + 1 >= MAX_FAILURES;
                    n.last = { outcome: 'unauthorized', clearance: 0, level: lvl, wasLocked: false };
                    n.auditFailures++;
                    n.realFailures++;
                    out.push(n);
                }
            }
        }
        if (s.locked[ip]) {                       // Unlock
            const n = clone(s);
            n.locked[ip] = false;
            n.failures[ip] = 0;
            out.push(n);
        }
    });
    return out;
}

const invariants: Record<string, (s: State) => boolean> = {
    NoReadUp: (s) => s.last.outcome !== 'granted' || s.last.clearance >= s.last.level,
    AnonymousOnlyPublic: (s) =>
        !(s.last.outcome === 'granted' && s.last.clearance === ANON) || s.last.level === 0,
    NoGrantWhileLocked: (s) =>
        !(s.last.outcome === 'granted' && s.last.clearance > 0) || !s.last.wasLocked,
    SecretNeverReadable: (s) => s.last.outcome !== 'granted' || s.last.level < 3,
    AuditComplete: (s) => s.auditFailures === s.realFailures && s.auditDenied === s.realDenied,
    LockoutBound: (s) => s.failures.every((f) => f <= MAX_FAILURES),
};

test('модель монитора обращений: все инварианты выполняются во всех достижимых состояниях', () => {
    const init: State = {
        failures: [0, 0],
        locked: [false, false],
        last: { outcome: 'none', clearance: 0, level: 0, wasLocked: false },
        auditFailures: 0, realFailures: 0, auditDenied: 0, realDenied: 0,
    };
    const seen = new Set([key(init)]);
    const queue = [init];
    while (queue.length) {
        const s = queue.shift()!;
        for (const [name, inv] of Object.entries(invariants)) {
            assert.ok(inv(s), `нарушен инвариант ${name} в состоянии ${key(s)}`);
        }
        // StateBound — ограничение пространства, как CONSTRAINT в .cfg
        if (s.auditFailures > BOUND || s.auditDenied > BOUND) continue;
        for (const n of next(s)) {
            const k = key(n);
            if (!seen.has(k)) {
                seen.add(k);
                queue.push(n);
            }
        }
    }
    console.log(`# проверено различных состояний: ${seen.size}`);
    assert.ok(seen.size > 1000);
});

test('правило модели совпадает с реализацией canRead()', () => {
    for (const clearance of LEVELS) {
        for (const lvl of LEVELS) {
            assert.equal(
                canRead({ id: 's', clearance: clearance as Level }, lvl as Level),
                clearance >= lvl,
            );
        }
    }
});
