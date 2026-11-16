import type { AddressInfo } from 'node:net';
import bcrypt from 'bcryptjs';
import { createApp, type Db } from '../src/app.ts';
import { createMemoryAuditLogger } from '../src/audit/auditLog.ts';

export const ADMIN_TOKEN = 'test-admin-token-9f2c';
export const ADMIN_HASH = bcrypt.hashSync(ADMIN_TOKEN, 4);

export function fakeDb(rows: any[] = []) {
    const calls: { text: string; params?: unknown[] }[] = [];
    const db: Db = {
        async query(text, params) {
            calls.push({ text, params });
            if (/^\s*SELECT COUNT/i.test(text)) return { rows: [{ count: String(rows.length) }] };
            if (/INSERT INTO contact_requests/i.test(text)) return { rows: [{ id: 42 }] };
            return { rows };
        },
    };
    return { db, calls };
}

export async function startApp(opts: { requireHttps?: boolean; rows?: any[] } = {}) {
    const { db, calls } = fakeDb(opts.rows);
    const audit = createMemoryAuditLogger();
    const app = createApp({
        db,
        audit,
        config: {
            adminTokenHash: ADMIN_HASH,
            corsOrigins: ['http://localhost:5173'],
            requireHttps: opts.requireHttps ?? false,
            trustProxy: true,
        },
    });
    const server = app.listen(0);
    await new Promise((r) => server.once('listening', r));
    const { port } = server.address() as AddressInfo;
    return {
        url: `http://127.0.0.1:${port}`,
        calls,
        audit,
        close: () => new Promise((r) => server.close(r)),
    };
}

export const validContact = {
    name: 'Ivan',
    phone_number: '+79001234567',
    email: 'ivan@example.com',
    budget: '',
    service: 'Residential',
    message: 'Hello',
    consent: true,
};
