// Доработка №2: доверенный путь — HTTPS + HSTS (слайд 12; Конституция РФ ст. 23, 149-ФЗ).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { startApp } from './helpers.ts';

test('HTTP-запрос перенаправляется на HTTPS при requireHttps', async () => {
    const s = await startApp({ requireHttps: true });
    try {
        const res = await fetch(`${s.url}/blog`, { redirect: 'manual' });
        assert.equal(res.status, 308);
        assert.match(res.headers.get('location') ?? '', /^https:\/\//);
    } finally {
        await s.close();
    }
});

test('за прокси с X-Forwarded-Proto: https отдаётся HSTS', async () => {
    const s = await startApp({ requireHttps: true });
    try {
        const res = await fetch(`${s.url}/blog`, { headers: { 'X-Forwarded-Proto': 'https' } });
        assert.equal(res.status, 200);
        assert.match(res.headers.get('strict-transport-security') ?? '', /max-age=31536000/);
    } finally {
        await s.close();
    }
});

test('защитные заголовки и отсутствие X-Powered-By', async () => {
    const s = await startApp();
    try {
        const res = await fetch(`${s.url}/team`);
        assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
        assert.equal(res.headers.get('x-frame-options'), 'DENY');
        assert.equal(res.headers.get('x-powered-by'), null);
    } finally {
        await s.close();
    }
});

test('CORS разрешён только для доверенного источника', async () => {
    const s = await startApp();
    try {
        const good = await fetch(`${s.url}/team`, { headers: { Origin: 'http://localhost:5173' } });
        assert.equal(good.headers.get('access-control-allow-origin'), 'http://localhost:5173');
        const evil = await fetch(`${s.url}/team`, { headers: { Origin: 'https://evil.example' } });
        assert.equal(evil.headers.get('access-control-allow-origin'), null);
    } finally {
        await s.close();
    }
});
