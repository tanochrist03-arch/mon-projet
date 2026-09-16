-- ============================================================================
--  Email Domain Security — CONTRÔLE PRÉALABLE (lecture seule)
--
--  À exécuter AVANT sql/001_domain_analyses.sql, dans Supabase -> SQL Editor.
--  Ce fichier ne contient QUE des SELECT : aucune création, aucune
--  modification, aucune suppression, aucune donnée touchée.
--
--  Objectif : savoir si la table domain_analyses existe déjà et, si oui,
--  si son schéma est compatible avec le code (sinon l'exécution du script
--  de création ne suffirait pas et les enregistrements échoueraient).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 0. La table existe-t-elle ?  (une seule cellule de réponse)
--    NULL      -> elle n'existe pas  -> le script 001 la créera
--    domain_analyses -> elle existe  -> comparez ses colonnes (requête 1)
-- ---------------------------------------------------------------------------
select to_regclass('public.domain_analyses') as table_existante;

-- ---------------------------------------------------------------------------
-- 1. Colonnes de la table (requête demandée, + valeur par défaut)
--    Attendu si tout va bien : id, created_at, email, domain, reputation,
--    risk, risk_score, reasons, signals, sources, duration_ms, app_version
--    0 ligne = table inexistante (cas normal ici).
-- ---------------------------------------------------------------------------
select column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public' and table_name = 'domain_analyses'
order by ordinal_position;

-- ---------------------------------------------------------------------------
-- 2. RLS déjà actif ? (true = protection en place)
-- ---------------------------------------------------------------------------
select c.relname, c.relrowsecurity, c.relforcerowsecurity
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relname = 'domain_analyses';

-- ---------------------------------------------------------------------------
-- 3. Politiques RLS existantes (doit être vide)
-- ---------------------------------------------------------------------------
select policyname, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'domain_analyses';

-- ---------------------------------------------------------------------------
-- 4. Privilèges des rôles exposés par l'API publique (doit être vide)
-- ---------------------------------------------------------------------------
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'public' and table_name = 'domain_analyses'
  and grantee in ('anon', 'authenticated');

-- ---------------------------------------------------------------------------
-- 5. Index existants
-- ---------------------------------------------------------------------------
select indexname, indexdef
from pg_indexes
where schemaname = 'public' and tablename = 'domain_analyses';

-- ---------------------------------------------------------------------------
-- 6. Tables du même nom dans un autre schéma (conflit éventuel)
-- ---------------------------------------------------------------------------
select table_schema, table_name, table_type
from information_schema.tables
where table_name = 'domain_analyses';
