-- Runs once, as the postgres superuser, when the data volume is first created.
-- The app role is deliberately NOT a superuser and cannot bypass RLS:
-- superusers ignore Row-Level Security entirely, so the application must
-- never connect as one. It still OWNS the database (can run migrations);
-- FORCE ROW LEVEL SECURITY in migration 0001 keeps RLS applied to owners.
CREATE ROLE argus LOGIN PASSWORD 'argus'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

CREATE DATABASE argus OWNER argus;

\connect argus
CREATE EXTENSION IF NOT EXISTS vector;
