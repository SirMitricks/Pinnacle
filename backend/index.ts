import pg from 'pg';
import { loadConfig } from './src/config.ts';
import { createApp } from './src/app.ts';
import { createFileAuditLogger } from './src/audit/auditLog.ts';

const config = loadConfig();
const audit = createFileAuditLogger(config.auditLogPath);

const pool = new pg.Pool({
    host: config.db.host,
    port: config.db.port,
    database: config.db.database,
    user: config.db.user,
    password: config.db.password,
});

const app = createApp({ db: pool, audit, config });

app.listen(config.port, () => {
    audit.log('app.start', { env: config.env, requireHttps: config.requireHttps });
    console.log(`Server started on port ${config.port}`);
});
