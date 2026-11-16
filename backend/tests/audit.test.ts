// Доработка №4: журнал аудита с защитой от подделки (слайд 12; 149-ФЗ — цели защиты).
// Доработка №6: согласие на обработку ПДн проверяется на сервере (152-ФЗ, слайд 3).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createFileAuditLogger, verifyAuditLog } from '../src/audit/auditLog.ts';
import { startApp, validContact } from './helpers.ts';

test('цепочка хешей проходит проверку', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'audit-')), 'audit.log');
    const log = createFileAuditLogger(path);
    log.log('app.start');
    log.log('contact.created', { id: 1 });
    log.log('auth.failure', { ip: '1.2.3.4' });
    assert.deepEqual(verifyAuditLog(path), { ok: true, brokenAt: null });
});

test('правка записи задним числом обнаруживается', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'audit-')), 'audit.log');
    const log = createFileAuditLogger(path);
    log.log('auth.failure', { ip: '1.2.3.4' });
    log.log('auth.failure', { ip: '1.2.3.4' });
    log.log('admin.read', { count: 3 });
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    lines[1] = lines[1].replace('1.2.3.4', '9.9.9.9');
    writeFileSync(path, lines.join('\n') + '\n');
    assert.deepEqual(verifyAuditLog(path), { ok: false, brokenAt: 2 });
});

test('удаление строки обнаруживается', () => {
    const path = join(mkdtempSync(join(tmpdir(), 'audit-')), 'audit.log');
    const log = createFileAuditLogger(path);
    log.log('auth.failure', { ip: 'a' });
    log.log('auth.failure', { ip: 'b' });
    log.log('auth.failure', { ip: 'c' });
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    writeFileSync(path, [lines[0], lines[2]].join('\n') + '\n');
    assert.equal(verifyAuditLog(path).ok, false);
});

test('заявка без согласия отклоняется и не попадает в БД', async () => {
    const s = await startApp();
    try {
        const res = await fetch(`${s.url}/contact`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...validContact, consent: false }),
        });
        assert.equal(res.status, 400);
        assert.equal(s.calls.length, 0);
    } finally {
        await s.close();
    }
});

test('заявка с согласием сохраняется, а в журнал не попадают ПДн', async () => {
    const s = await startApp();
    try {
        const res = await fetch(`${s.url}/contact`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(validContact),
        });
        assert.equal(res.status, 201);
        assert.match(s.calls[0].text, /consent_given/);
        const created = s.audit.records.find((r) => r.event === 'contact.created');
        assert.deepEqual(created?.details, { id: 42 });
        const dump = JSON.stringify(s.audit.records);
        assert.ok(!dump.includes(validContact.email) && !dump.includes(validContact.phone_number));
    } finally {
        await s.close();
    }
});
