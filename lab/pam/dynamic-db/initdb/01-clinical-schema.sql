-- =============================================================================
-- clinical-db bootstrap (runs once, on an empty data volume, as the bootstrap
-- superuser). SYNTHETIC DATA ONLY: invented MRNs and names, no real patient.
--
-- Privilege model (least privilege, nothing granted to PUBLIC):
--   clinical_reader  NOLOGIN group: CONNECT + USAGE + SELECT on schema
--                    `clinical` only. Dynamic logins are made members of it.
--   billing          a second schema nobody in this segment may read: the
--                    negative control for "one schema, SELECT only".
--   vault_admin      created by setup.sh (its password must not sit in a file
--                    in the repo): CREATEROLE + ADMIN on clinical_reader, but
--                    NOT a member it can use - Vault's own account can issue
--                    access to PHI without being able to read it.
-- =============================================================================

\set ON_ERROR_STOP on

-- Nothing by default: PUBLIC loses CONNECT/TEMP on this database and every
-- right on the public schema - and CONNECT/TEMP on the server's other
-- databases too, so a dynamic login cannot open the `postgres` maintenance
-- database (or template1) and create temporary objects there.
REVOKE ALL ON DATABASE clinical FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CONNECT, TEMPORARY ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT, TEMPORARY ON DATABASE template1 FROM PUBLIC;

-- Statement audit (HIPAA 164.312(b)): every statement run in `clinical` is
-- logged, with the session's user in the line prefix (compose
-- log_line_prefix), so a dynamic login's PHI reads are recorded under its
-- person-bearing v-<person>-* name. The superuser (and, from setup.sh,
-- vault_admin) are exempt: their statements set passwords. Role settings
-- override database settings, so the exemption holds inside `clinical`.
ALTER DATABASE clinical SET log_statement = 'all';
ALTER ROLE postgres SET log_statement = 'none';

CREATE SCHEMA clinical;
CREATE SCHEMA billing;

CREATE TABLE clinical.patients (
    mrn          text PRIMARY KEY,           -- synthetic (CH- prefix)
    display_name text NOT NULL,              -- invented
    birth_year   integer NOT NULL,
    home_site    text NOT NULL
);

CREATE TABLE clinical.encounters (
    encounter_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mrn          text NOT NULL REFERENCES clinical.patients (mrn),
    site         text NOT NULL,
    unit         text NOT NULL,
    admitted_at  timestamptz NOT NULL,
    discharged_at timestamptz
);

CREATE TABLE billing.claims (
    claim_id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mrn          text NOT NULL REFERENCES clinical.patients (mrn),
    payer        text NOT NULL,
    amount_usd   numeric(10, 2) NOT NULL
);

INSERT INTO clinical.patients (mrn, display_name, birth_year, home_site) VALUES
    ('CH-000101', 'Test Patient Alpha',   1961, 'Contoso Health North'),
    ('CH-000102', 'Test Patient Bravo',   1978, 'Contoso Health North'),
    ('CH-000103', 'Test Patient Charlie', 1990, 'Contoso Health South'),
    ('CH-000104', 'Test Patient Delta',   2004, 'Contoso Health South');

INSERT INTO clinical.encounters (mrn, site, unit, admitted_at, discharged_at) VALUES
    ('CH-000101', 'Contoso Health North', 'ED',        now() - interval '3 days', now() - interval '2 days'),
    ('CH-000102', 'Contoso Health North', 'Cardiology', now() - interval '1 day', NULL),
    ('CH-000103', 'Contoso Health South', 'ICU',       now() - interval '6 hours', NULL),
    ('CH-000104', 'Contoso Health South', 'Pediatrics', now() - interval '10 days', now() - interval '8 days');

INSERT INTO billing.claims (mrn, payer, amount_usd) VALUES
    ('CH-000101', 'Synthetic Payer A', 1840.00),
    ('CH-000104', 'Synthetic Payer B',  612.50);

CREATE ROLE clinical_reader NOLOGIN;
GRANT CONNECT ON DATABASE clinical TO clinical_reader;
GRANT USAGE ON SCHEMA clinical TO clinical_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA clinical TO clinical_reader;
-- Tables added to `clinical` later by the owner are readable too; nothing else is.
ALTER DEFAULT PRIVILEGES IN SCHEMA clinical GRANT SELECT ON TABLES TO clinical_reader;
