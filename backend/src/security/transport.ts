// Доверенный путь (слайд 12): принудительный HTTPS, HSTS и защитные заголовки.
// Доработка №2: Конституция РФ ст. 23, 149-ФЗ; FPT_TDC.1 / FTP_TRP.1 (ИСО 15408).
import type { NextFunction, Request, Response } from 'express';

export const HSTS_VALUE = 'max-age=31536000; includeSubDomains';

export function securityHeaders(requireHttps: boolean) {
    return (_req: Request, res: Response, next: NextFunction) => {
        res.removeHeader('X-Powered-By');
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
        res.setHeader('Referrer-Policy', 'no-referrer');
        // API отдаёт только JSON — никакие скрипты/фреймы не нужны.
        res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
        if (requireHttps) {
            res.setHeader('Strict-Transport-Security', HSTS_VALUE);
        }
        next();
    };
}

/** Запросы по HTTP перенаправляются на HTTPS (308 сохраняет метод и тело). */
export function enforceHttps(requireHttps: boolean) {
    return (req: Request, res: Response, next: NextFunction) => {
        if (!requireHttps || req.secure) {
            return next();
        }
        const host = req.headers.host ?? 'localhost';
        res.redirect(308, `https://${host}${req.originalUrl}`);
    };
}
