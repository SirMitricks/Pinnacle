// Монитор обращений (слайд 10) и принудительное управление доступом на основе меток (слайд 11).
// Доработка №3. Единственная точка принятия решения о доступе: ни один маршрут
// не регистрируется в обход функции secureRoute(), а проверку полноты выполняет
// assertCompleteMediation() при старте приложения и в тестах.
import bcrypt from 'bcryptjs';
import type { Express, NextFunction, Request, RequestHandler, Response } from 'express';
import type { AuditLogger } from '../audit/auditLog.ts';

/** Метки безопасности (уровни конфиденциальности). */
export const Level = {
    PUBLIC: 0,
    INTERNAL: 1,
    CONFIDENTIAL: 2,
    SECRET: 3,
} as const;
export type Level = (typeof Level)[keyof typeof Level];

export const LEVEL_NAME: Record<Level, string> = {
    0: 'public',
    1: 'internal',
    2: 'confidential',
    3: 'secret',
};

export interface Subject {
    id: string;
    clearance: Level;
}

export const ANONYMOUS: Subject = { id: 'anonymous', clearance: Level.PUBLIC };

/** Правило мандатного доступа: чтение разрешено, если допуск субъекта не ниже метки объекта. */
export function canRead(subject: Subject, objectLevel: Level): boolean {
    return subject.clearance >= objectLevel;
}

// ---------------------------------------------------------------------------
// Аутентификация администратора + блокировка после N неудачных попыток
// ---------------------------------------------------------------------------

export const MAX_FAILURES = 5;
export const LOCKOUT_MS = 15 * 60 * 1000;

interface FailureState {
    count: number;
    lockedUntil: number;
}

export interface AccessControl {
    secureRoute(
        app: Express,
        method: 'get' | 'post',
        path: string,
        level: Level,
        handler: RequestHandler,
    ): void;
    assertCompleteMediation(app: Express): void;
    readonly registry: ReadonlyMap<string, Level>;
}

export function createAccessControl(opts: {
    adminTokenHash: string | null;
    audit: AuditLogger;
    now?: () => number;
}): AccessControl {
    const now = opts.now ?? Date.now;
    const failures = new Map<string, FailureState>();
    const registry = new Map<string, Level>();

    function authenticate(req: Request): Subject | 'locked' | 'invalid' {
        const header = req.headers.authorization;
        if (!header) return ANONYMOUS;

        const ip = req.ip ?? 'unknown';
        const state = failures.get(ip);
        if (state && state.lockedUntil > now()) return 'locked';

        const token = header.startsWith('Bearer ') ? header.slice(7) : '';
        const ok =
            opts.adminTokenHash !== null &&
            token.length > 0 &&
            bcrypt.compareSync(token, opts.adminTokenHash);

        if (!ok) {
            const next = { count: (state?.count ?? 0) + 1, lockedUntil: 0 };
            if (next.count >= MAX_FAILURES) {
                next.lockedUntil = now() + LOCKOUT_MS;
                opts.audit.log('auth.lockout', { ip });
            }
            failures.set(ip, next);
            opts.audit.log('auth.failure', { ip, attempt: next.count });
            return 'invalid';
        }

        failures.delete(ip);
        opts.audit.log('auth.success', { ip, subject: 'admin' });
        return { id: 'admin', clearance: Level.CONFIDENTIAL };
    }

    /** Промежуточный обработчик монитора обращений. */
    function mediate(level: Level): RequestHandler {
        return (req: Request, res: Response, next: NextFunction) => {
            const subject = authenticate(req);
            if (subject === 'locked') {
                return res.status(429).json({ message: 'Слишком много попыток, доступ временно заблокирован' });
            }
            if (subject === 'invalid') {
                return res.status(401).json({ message: 'Неверные учётные данные' });
            }
            if (!canRead(subject, level)) {
                opts.audit.log('access.denied', {
                    path: req.path,
                    subject: subject.id,
                    required: LEVEL_NAME[level],
                });
                return res.status(subject === ANONYMOUS ? 401 : 403).json({ message: 'Доступ запрещён' });
            }
            res.locals.subject = subject;
            next();
        };
    }

    return {
        registry,
        secureRoute(app, method, path, level, handler) {
            registry.set(`${method.toUpperCase()} ${path}`, level);
            app[method](path, mediate(level), handler);
        },
        assertCompleteMediation(app) {
            // Express 5: маршруты лежат в app.router.stack
            const router = (app as unknown as { router: { stack: any[] } }).router;
            for (const layer of router.stack) {
                if (!layer.route) continue;
                for (const method of Object.keys(layer.route.methods)) {
                    const key = `${method.toUpperCase()} ${layer.route.path}`;
                    if (!registry.has(key)) {
                        throw new Error(`Маршрут ${key} зарегистрирован в обход монитора обращений`);
                    }
                }
            }
        },
    };
}

