-- Миграция для ветки audit.
-- Метки безопасности (слайд 11) и фиксация согласия на обработку ПДн (152-ФЗ, ст. 9).
-- classification: 0 = public, 1 = internal, 2 = confidential, 3 = secret

ALTER TABLE contact_requests ADD COLUMN IF NOT EXISTS classification SMALLINT  NOT NULL DEFAULT 2;
ALTER TABLE contact_requests ADD COLUMN IF NOT EXISTS consent_given  BOOLEAN   NOT NULL DEFAULT FALSE;
ALTER TABLE contact_requests ADD COLUMN IF NOT EXISTS consent_at     TIMESTAMP;

ALTER TABLE contact_requests
    ADD CONSTRAINT contact_requests_classification_chk CHECK (classification BETWEEN 0 AND 3);

-- Заявка без согласия не может попасть в таблицу даже в обход API.
ALTER TABLE contact_requests
    ADD CONSTRAINT contact_requests_consent_chk CHECK (consent_given = TRUE) NOT VALID;

-- Публичный контент явно помечается как public.
ALTER TABLE testimonials ADD COLUMN IF NOT EXISTS classification SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE projects     ADD COLUMN IF NOT EXISTS classification SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE services     ADD COLUMN IF NOT EXISTS classification SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE team         ADD COLUMN IF NOT EXISTS classification SMALLINT NOT NULL DEFAULT 0;
ALTER TABLE blog         ADD COLUMN IF NOT EXISTS classification SMALLINT NOT NULL DEFAULT 0;
