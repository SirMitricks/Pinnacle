// Доработки №3 и №5: монитор обращений, метки безопасности и тесты на его обход (слайды 10, 11).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { ADMIN_TOKEN, startApp } from './helpers.ts';
import {
    ANONYMOUS,
    canRead,
    createAccessControl,
    Level,
    MAX_FAILURES,
} from '../src/security/accessControl.ts';
import { createMemoryAuditLogger } from '../src/audit/auditLog.ts';

test('правило мандатного доступа: допуск >= метки', () => {
    assert.equal(canRead(ANONYMOUS, Level.PUBLIC), true);
    assert.equal(canRead(ANONYMOUS, Level.CONFIDENTIAL), false);
    assert.equal(canRead({ id: 'admin', clearance: Level.CONFIDENTIAL }, Level.CONFIDENTIAL), true);
    assert.equal(canRead({ id: 'admin', clearance: Level.CONFIDENTIAL }, Level.SECRET), false);
});

test('обход: аноним не получает заявки с ПДн', async () => {
    const s = await startApp({ rows: [{ id: 1, email: 'a@b.c' }] });
    try {
        const res = await fetch(`${s.url}/admin/contact-requests`);
        assert.equal(res.status, 401);
        assert.equal(s.calls.length, 0, 'запрос к БД не должен выполняться');
        assert.ok(s.audit.records.some((r) => r.event === 'access.denied'));
    } finally {
        await s.close();
    }
});

test('обход: подделанный токен отклоняется', async () => {
    const s = await startApp();
    try {
        const res = await fetch(`${s.url}/admin/contact-requests`, {
            headers: { Authorization: 'Bearer guessed-token' },
        });
        assert.equal(res.status, 401);
        assert.equal(s.calls.length, 0);
    } finally {
        await s.close();
    }
});

test('администратор читает только строки с меткой <= своего допуска', async () => {
    const s = await startApp({ rows: [{ id: 1 }] });
    try {
        const res = await fetch(`${s.url}/admin/contact-requests`, {
            headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
        });
        assert.equal(res.status, 200);
        const q = s.calls.at(-1)!;
        assert.match(q.text, /classification <= \$1/);
        assert.deepEqual(q.params, [Level.CONFIDENTIAL]);
        assert.ok(s.audit.records.some((r) => r.event === 'admin.read'));
    } finally {
        await s.close();
    }
});

test(`блокировка после ${MAX_FAILURES} неудачных попыток`, async () => {
    const s = await startApp();
    try {
        for (let i = 0; i < MAX_FAILURES; i++) {
            await fetch(`${s.url}/admin/contact-requests`, { headers: { Authorization: 'Bearer x' } });
        }
        // даже верный токен теперь отклоняется
        const res = await fetch(`${s.url}/admin/contact-requests`, {
            headers: { Authorization: `Bearer ${ADMIN_TOKEN}` },
        });
        assert.equal(res.status, 429);
        assert.ok(s.audit.records.some((r) => r.event === 'auth.lockout'));
    } finally {
        await s.close();
    }
});

test('полнота: маршрут в обход монитора обнаруживается', () => {
    const app = express();
    const ac = createAccessControl({ adminTokenHash: null, audit: createMemoryAuditLogger() });
    ac.secureRoute(app, 'get', '/ok', Level.PUBLIC, (_req, res) => res.end());
    app.get('/backdoor', (_req, res) => res.end());
    assert.throws(() => ac.assertCompleteMediation(app), /в обход монитора обращений/);
});

test('некорректный id отклоняется до обращения к БД', async () => {
    const s = await startApp();
    try {
        const res = await fetch(`${s.url}/projects/1%20OR%201=1`);
        assert.equal(res.status, 400);
        assert.equal(s.calls.length, 0);
    } finally {
        await s.close();
    }
});
