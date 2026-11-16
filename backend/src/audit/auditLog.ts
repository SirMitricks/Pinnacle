// Журнал аудита (подотчётность, слайд 12; FAU_GEN.1, FAU_STG.2 по ИСО 15408).
// Доработка №4. Каждая запись — JSON-строка, содержащая хеш предыдущей записи,
// поэтому удаление или правка любой строки обнаруживается функцией verifyAuditLog.
// Персональные данные в журнал не пишутся (152-ФЗ): только идентификаторы событий.
import { createHash } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';

export type AuditEvent =
    | 'app.start'
    | 'contact.created'
    | 'contact.rejected'
    | 'auth.success'
    | 'auth.failure'
    | 'auth.lockout'
    | 'access.denied'
    | 'admin.read'
    | 'server.error';

export interface AuditRecord {
    ts: string;
    event: AuditEvent;
    details: Record<string, unknown>;
    prev: string;
    hash: string;
}

export interface AuditLogger {
    log(event: AuditEvent, details?: Record<string, unknown>): AuditRecord;
}

const GENESIS = '0'.repeat(64);

function digest(prev: string, ts: string, event: string, details: unknown): string {
    return createHash('sha256')
        .update(`${prev}|${ts}|${event}|${JSON.stringify(details)}`)
        .digest('hex');
}

function lastHash(path: string): string {
    if (!existsSync(path)) return GENESIS;
    const lines = readFileSync(path, 'utf8').trim().split('\n').filter(Boolean);
    if (!lines.length) return GENESIS;
    return (JSON.parse(lines[lines.length - 1]) as AuditRecord).hash;
}

export function createFileAuditLogger(path: string): AuditLogger {
    mkdirSync(dirname(path), { recursive: true });
    let prev = lastHash(path);

    return {
        log(event, details = {}) {
            const ts = new Date().toISOString();
            const hash = digest(prev, ts, event, details);
            const record: AuditRecord = { ts, event, details, prev, hash };
            // Флаг 'a' — только дозапись (append-only).
            appendFileSync(path, JSON.stringify(record) + '\n', { flag: 'a' });
            prev = hash;
            return record;
        },
    };
}

/** Проверка целостности журнала. Возвращает номер первой повреждённой строки или null. */
export function verifyAuditLog(path: string): { ok: boolean; brokenAt: number | null } {
    const lines = readFileSync(path, 'utf8').trim().split('\n').filter(Boolean);
    let prev = GENESIS;
    for (let i = 0; i < lines.length; i++) {
        const r = JSON.parse(lines[i]) as AuditRecord;
        if (r.prev !== prev || r.hash !== digest(r.prev, r.ts, r.event, r.details)) {
            return { ok: false, brokenAt: i + 1 };
        }
        prev = r.hash;
    }
    return { ok: true, brokenAt: null };
}

/** Журнал в памяти — для тестов. */
export function createMemoryAuditLogger(): AuditLogger & { records: AuditRecord[] } {
    const records: AuditRecord[] = [];
    let prev = GENESIS;
    return {
        records,
        log(event, details = {}) {
            const ts = new Date().toISOString();
            const hash = digest(prev, ts, event, details);
            const record = { ts, event, details, prev, hash };
            records.push(record);
            prev = hash;
            return record;
        },
    };
}
