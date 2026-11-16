// Проверка целостности журнала аудита: npm run audit:verify [путь]
import { verifyAuditLog } from '../src/audit/auditLog.ts';

const path = process.argv[2] ?? process.env.AUDIT_LOG_PATH ?? 'logs/audit.log';
const result = verifyAuditLog(path);
if (result.ok) {
    console.log(`OK: журнал ${path} не изменялся`);
} else {
    console.error(`НАРУШЕНА ЦЕЛОСТНОСТЬ: строка ${result.brokenAt} файла ${path}`);
    process.exit(1);
}
