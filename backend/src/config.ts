// Конфигурация приложения. Все секреты берутся только из переменных окружения
// (доработка №1: УК РФ ст. 272, слайд 4 — отсутствие захардкоженных паролей).

export interface AppConfig {
    env: 'development' | 'test' | 'production';
    port: number;
    db: {
        host: string;
        port: number;
        database: string;
        user: string;
        password: string;
    };
    /** bcrypt-хеш токена администратора (сам токен в коде и в БД не хранится). */
    adminTokenHash: string | null;
    /** Разрешённые источники для CORS. */
    corsOrigins: string[];
    /** Требовать HTTPS и отдавать HSTS (в production — всегда). */
    requireHttps: boolean;
    /** Доверять заголовку X-Forwarded-Proto от обратного прокси (nginx). */
    trustProxy: boolean;
    /** Путь к журналу аудита (append-only, с хеш-цепочкой). */
    auditLogPath: string;
}

export class ConfigError extends Error {}

type Env = Record<string, string | undefined>;

function required(env: Env, name: string): string {
    const value = env[name];
    if (!value) {
        throw new ConfigError(`Не задана обязательная переменная окружения ${name}`);
    }
    return value;
}

export function loadConfig(env: Env = process.env): AppConfig {
    const mode = (env.NODE_ENV ?? 'development') as AppConfig['env'];
    const isProd = mode === 'production';

    // Отладочный обход проверок в production запрещён (неизменность ядра безопасности, слайд 10).
    if (isProd && (env.BYPASS_AUTH || env.DEBUG === 'true')) {
        throw new ConfigError('BYPASS_AUTH/DEBUG недопустимы в production');
    }

    const requireHttps = isProd ? true : env.REQUIRE_HTTPS === 'true';

    return {
        env: mode,
        port: Number(env.PORT ?? 5000),
        db: {
            host: env.DB_HOST ?? 'localhost',
            port: Number(env.DB_PORT ?? 5432),
            database: env.DB_NAME ?? 'postgres',
            user: env.DB_USER ?? 'postgres',
            // Пароль БД не имеет значения по умолчанию ни в одном режиме.
            password: required(env, 'DB_PASSWORD'),
        },
        adminTokenHash: env.ADMIN_TOKEN_HASH ?? null,
        corsOrigins: (env.CORS_ORIGINS ?? 'http://localhost:5173')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean),
        requireHttps,
        trustProxy: env.TRUST_PROXY === 'true',
        auditLogPath: env.AUDIT_LOG_PATH ?? 'logs/audit.log',
    };
}
