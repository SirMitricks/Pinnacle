// Доработка №1: секреты только из окружения (УК РФ ст. 272, слайд 4).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ConfigError, loadConfig } from '../src/config.ts';

test('без DB_PASSWORD приложение не стартует', () => {
    assert.throws(() => loadConfig({ NODE_ENV: 'production' }), ConfigError);
    assert.throws(() => loadConfig({}), ConfigError);
});

test('пароль берётся из окружения', () => {
    const cfg = loadConfig({ DB_PASSWORD: 's3cret' });
    assert.equal(cfg.db.password, 's3cret');
});

test('в production HTTPS обязателен и BYPASS_AUTH запрещён', () => {
    assert.equal(loadConfig({ NODE_ENV: 'production', DB_PASSWORD: 'x' }).requireHttps, true);
    assert.throws(
        () => loadConfig({ NODE_ENV: 'production', DB_PASSWORD: 'x', BYPASS_AUTH: '1' }),
        ConfigError,
    );
});

test('в исходном коде нет захардкоженного пароля БД', () => {
    for (const file of ['index.ts', 'src/app.ts', 'src/config.ts']) {
        const src = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
        assert.doesNotMatch(src, /password:\s*['"][^'"]+['"]/, file);
    }
});
