import express, { type Express, type Request, type Response } from 'express';
import cors from 'cors';
import type { AppConfig } from './config.ts';
import type { AuditLogger } from './audit/auditLog.ts';
import { createAccessControl, Level, type Subject } from './security/accessControl.ts';
import { enforceHttps, securityHeaders } from './security/transport.ts';

export interface Db {
    query(text: string, params?: unknown[]): Promise<{ rows: any[] }>;
}

export interface AppDeps {
    db: Db;
    audit: AuditLogger;
    config: Pick<AppConfig, 'adminTokenHash' | 'corsOrigins' | 'requireHttps' | 'trustProxy'>;
}

const MAX_PAGE = 50;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;

function page(req: Request) {
    const limit = Math.min(Math.max(Number(req.query.limit) || 6, 1), MAX_PAGE);
    const offset = Math.max(Number(req.query.offset) || 0, 0);
    return { limit, offset };
}

function isId(value: unknown): value is string {
    return typeof value === 'string' && /^\d{1,9}$/.test(value);
}

function str(value: unknown, min: number, max: number): string | null {
    if (typeof value !== 'string') return min === 0 ? '' : null;
    const v = value.trim();
    return v.length >= min && v.length <= max ? v : null;
}

export function createApp({ db, audit, config }: AppDeps): Express {
    const app = express();
    app.disable('x-powered-by');
    app.set('trust proxy', config.trustProxy);

    app.use(enforceHttps(config.requireHttps));
    app.use(securityHeaders(config.requireHttps));
    app.use(cors({ origin: config.corsOrigins }));
    app.use(express.json({ limit: '20kb' }));

    const ac = createAccessControl({ adminTokenHash: config.adminTokenHash, audit });

    const fail = (res: Response, req: Request, error: unknown, message: string) => {
        console.error(error);
        audit.log('server.error', { path: req.path });
        res.status(500).json({ message });
    };

    // ----------------------------- PUBLIC -----------------------------

    ac.secureRoute(app, 'get', '/testimonials', Level.PUBLIC, async (req, res) => {
        try {
            const params: string[] = [];
            const conditions = ['is_active = TRUE'];
            if (typeof req.query.position === 'string') {
                params.push(req.query.position);
                conditions.push(`position = $${params.length}`);
            }
            const result = await db.query(
                `SELECT id, text, author_name, author_role, author_avatar, rating, position
                 FROM testimonials WHERE ${conditions.join(' AND ')} ORDER BY sort_order, id`,
                params,
            );
            res.json(result.rows);
        } catch (e) {
            fail(res, req, e, 'Ошибка при получении отзывов');
        }
    });

    ac.secureRoute(app, 'get', '/projects', Level.PUBLIC, async (req, res) => {
        try {
            const { limit, offset } = page(req);
            const params: (string | number)[] = [];
            const conditions = ['is_active = TRUE'];

            if (typeof req.query.search === 'string' && req.query.search) {
                params.push(`%${req.query.search}%`);
                conditions.push(`name ILIKE $${params.length}`);
            }
            if (typeof req.query.location === 'string' && req.query.location) {
                params.push(req.query.location);
                conditions.push(`location = $${params.length}`);
            }
            if (isId(req.query.exclude)) {
                params.push(Number(req.query.exclude));
                conditions.push(`id <> $${params.length}`);
            }

            const where = `WHERE ${conditions.join(' AND ')}`;
            const listParams = [...params, limit, offset];
            const list = await db.query(
                `SELECT id, name, description, location, tag, image FROM projects ${where}
                 ORDER BY id LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
                listParams,
            );
            const total = await db.query(`SELECT COUNT(*) FROM projects ${where}`, params);
            res.json({ items: list.rows, total: Number(total.rows[0]?.count ?? 0) });
        } catch (e) {
            fail(res, req, e, 'Ошибка при получении проектов');
        }
    });

    ac.secureRoute(app, 'get', '/projects/:id', Level.PUBLIC, async (req, res) => {
        if (!isId(req.params.id)) return res.status(400).json({ message: 'Некорректный id' });
        try {
            const result = await db.query('SELECT * FROM projects WHERE id = $1 AND is_active = TRUE', [
                Number(req.params.id),
            ]);
            if (!result.rows.length) return res.status(404).json({ message: 'Not found' });
            res.json(result.rows[0]);
        } catch (e) {
            fail(res, req, e, 'Ошибка');
        }
    });

    ac.secureRoute(app, 'get', '/project-filters', Level.PUBLIC, async (req, res) => {
        try {
            const locations = await db.query('SELECT id, name FROM project_locations ORDER BY id');
            const types = await db.query('SELECT id, name FROM project_types ORDER BY id');
            const costs = await db.query('SELECT id, label, min, max FROM project_costs ORDER BY id');
            res.json({ locations: locations.rows, types: types.rows, costs: costs.rows });
        } catch (e) {
            fail(res, req, e, 'Ошибка при получении фильтров');
        }
    });

    ac.secureRoute(app, 'get', '/services', Level.PUBLIC, async (req, res) => {
        try {
            const params: string[] = [];
            const conditions = ['is_active = TRUE'];
            const category = req.query.category;
            if (typeof category === 'string' && category !== 'all') {
                params.push(category);
                conditions.push(`category = $${params.length}`);
            }
            const result = await db.query(
                `SELECT id, name, description, image, category FROM services
                 WHERE ${conditions.join(' AND ')} ORDER BY sort_order, id`,
                params,
            );
            res.json(result.rows);
        } catch (e) {
            fail(res, req, e, 'Ошибка при получении услуг');
        }
    });

    ac.secureRoute(app, 'get', '/services/main', Level.PUBLIC, async (req, res) => {
        try {
            const s = await db.query(
                `SELECT id, name, description FROM services WHERE category = 'residential' LIMIT 1`,
            );
            if (!s.rows.length) return res.status(404).json({ message: 'Category not found' });
            const sub = await db.query(
                `SELECT id, title, description, image FROM service_subsections
                 WHERE service_id = $1 AND is_active = TRUE ORDER BY sort_order, id`,
                [s.rows[0].id],
            );
            res.json({ ...s.rows[0], subsections: sub.rows });
        } catch (e) {
            fail(res, req, e, 'Server error');
        }
    });

    ac.secureRoute(app, 'get', '/team', Level.PUBLIC, async (req, res) => {
        try {
            const result = await db.query(
                `SELECT id, title, date_text, description, image FROM team
                 WHERE is_active = TRUE ORDER BY sort_order, id`,
            );
            res.json(result.rows);
        } catch (e) {
            fail(res, req, e, 'Ошибка при получении списка команды');
        }
    });

    ac.secureRoute(app, 'get', '/blog', Level.PUBLIC, async (req, res) => {
        try {
            const result = await db.query(
                `SELECT id, title, tag, description, date_text, image, category FROM blog
                 WHERE is_active = TRUE ORDER BY sort_order, id`,
            );
            res.json(result.rows);
        } catch (e) {
            fail(res, req, e, 'Ошибка при получении статей');
        }
    });

    ac.secureRoute(app, 'get', '/blog/list', Level.PUBLIC, async (req, res) => {
        try {
            const { limit, offset } = page(req);
            const params: (string | number)[] = [];
            const conditions = ['is_active = TRUE'];
            const category = req.query.category;
            if (typeof category === 'string' && category !== 'all') {
                params.push(category);
                conditions.push(`category = $${params.length}`);
            }
            const where = `WHERE ${conditions.join(' AND ')}`;
            const listParams = [...params, limit, offset];
            const list = await db.query(
                `SELECT id, title, tag, description, date_text, image, category FROM blog ${where}
                 ORDER BY sort_order, id LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
                listParams,
            );
            const total = await db.query(`SELECT COUNT(*) FROM blog ${where}`, params);
            res.json({ items: list.rows, total: Number(total.rows[0]?.count ?? 0) });
        } catch (e) {
            fail(res, req, e, 'Ошибка при получении статей');
        }
    });

    ac.secureRoute(app, 'get', '/blog/:id', Level.PUBLIC, async (req, res) => {
        if (!isId(req.params.id)) return res.status(400).json({ message: 'Некорректный id' });
        try {
            const result = await db.query('SELECT * FROM blog WHERE id = $1 AND is_active = TRUE', [
                Number(req.params.id),
            ]);
            if (!result.rows.length) return res.status(404).json({ message: 'Not found' });
            res.json(result.rows[0]);
        } catch (e) {
            fail(res, req, e, 'Ошибка');
        }
    });

    // Приём заявки с персональными данными (152-ФЗ): только при явном согласии.
    ac.secureRoute(app, 'post', '/contact', Level.PUBLIC, async (req, res) => {
        const body = req.body ?? {};
        const name = str(body.name, 1, 150);
        const phone = str(body.phone_number, 5, 40);
        const email = str(body.email, 3, 150);
        const budget = str(body.budget, 0, 100);
        const service = str(body.service, 0, 255);
        const message = str(body.message, 1, 5000);

        if (body.consent !== true) {
            audit.log('contact.rejected', { reason: 'no_consent' });
            return res.status(400).json({ message: 'Необходимо согласие на обработку персональных данных' });
        }
        if (!name || !phone || !email || !message || budget === null || service === null || !EMAIL_RE.test(email)) {
            audit.log('contact.rejected', { reason: 'validation' });
            return res.status(400).json({ message: 'Заполните обязательные поля' });
        }

        try {
            const result = await db.query(
                `INSERT INTO contact_requests
                    (name, phone_number, email, budget, service, message, consent_given, consent_at, classification)
                 VALUES ($1, $2, $3, $4, $5, $6, TRUE, CURRENT_TIMESTAMP, $7)
                 RETURNING id`,
                [name, phone, email, budget, service, message, Level.CONFIDENTIAL],
            );
            // В журнал — только идентификатор заявки, без ПДн.
            audit.log('contact.created', { id: result.rows[0]?.id });
            res.status(201).json({ success: true, message: 'Заявка успешно отправлена' });
        } catch (e) {
            fail(res, req, e, 'Ошибка при отправке сообщения');
        }
    });

    // --------------------------- CONFIDENTIAL ---------------------------

    ac.secureRoute(app, 'get', '/admin/contact-requests', Level.CONFIDENTIAL, async (req, res) => {
        const subject = res.locals.subject as Subject;
        try {
            // Вторая линия мандатного контроля — на уровне строк по полю classification.
            const result = await db.query(
                `SELECT id, name, phone_number, email, budget, service, message, created_at, classification
                 FROM contact_requests WHERE classification <= $1
                 ORDER BY created_at DESC LIMIT 100`,
                [subject.clearance],
            );
            audit.log('admin.read', { subject: subject.id, resource: 'contact_requests', count: result.rows.length });
            res.json(result.rows);
        } catch (e) {
            fail(res, req, e, 'Ошибка');
        }
    });

    ac.assertCompleteMediation(app);
    return app;
}
