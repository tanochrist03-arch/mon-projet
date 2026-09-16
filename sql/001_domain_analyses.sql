-- ============================================================================
--  Email Domain Security
--  Table d'enregistrement des analyses + durcissement RLS
--
--  ATTENTION : ce fichier n'est PAS encore exécuté.
--  Il doit être lancé par le propriétaire du projet, dans
--  Supabase -> SQL Editor, APRÈS validation explicite.
--
--  Script idempotent : peut être rejoué sans erreur.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Table domain_analyses
--    - `risk` accepte UNKNOWN uniquement pour le cas "domaine inexistant"
--      (aucun niveau LOW/MEDIUM/HIGH ne peut être calculé honnêtement).
--    - `risk_score` nullable pour la même raison.
--    - `reasons` : critères déclenchés, lisibles (traçabilité du score).
--    - `signals` : données brutes des sources (DNS, RDAP, jetables, urlscan, VT).
-- ---------------------------------------------------------------------------
create table if not exists public.domain_analyses (
  id           uuid primary key default gen_random_uuid(),
  created_at   timestamptz not null default now(),
  email        text not null,
  domain       text not null,
  reputation   text not null check (reputation in ('GOOD', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN')),
  risk         text not null check (risk in ('LOW', 'MEDIUM', 'HIGH', 'UNKNOWN')),
  risk_score   integer check (risk_score is null or (risk_score between 0 and 100)),
  reasons      jsonb not null default '[]'::jsonb,
  signals      jsonb not null default '{}'::jsonb,
  sources      text[] not null default '{}',
  duration_ms  integer,
  app_version  text default 'email-domain-security-1.0'
);

comment on table  public.domain_analyses is 'Email Domain Security — une ligne par analyse de domaine email. Écrite uniquement côté serveur.';
comment on column public.domain_analyses.reasons is 'Critères objectifs déclenchés, avec leur poids (traçabilité du score).';
comment on column public.domain_analyses.signals is 'Données brutes des sources : dns, rdap, disposable, urlscan, virustotal.';
comment on column public.domain_analyses.sources   is 'État par source : ok / error / disabled (dégradation).';

-- ---------------------------------------------------------------------------
-- 2. Index (recherche par domaine, historique récent)
-- ---------------------------------------------------------------------------
create index if not exists domain_analyses_domain_idx     on public.domain_analyses (domain);
create index if not exists domain_analyses_created_at_idx on public.domain_analyses (created_at desc);
create index if not exists domain_analyses_risk_idx       on public.domain_analyses (risk);

-- ---------------------------------------------------------------------------
-- 3. Durcissement : RLS activé et AUCUNE politique publique
--    -> la clé anon du navigateur ne peut ni lire ni écrire cette table ;
--    -> la clé secrète utilisée par /api/analyze (côté serveur) bypasse le RLS
--       et reste donc la seule voie d'écriture.
-- ---------------------------------------------------------------------------
alter table public.domain_analyses enable row level security;

-- Ceinture + bretelles : on retire explicitement les droits aux rôles exposés
-- par l'API publique (PostgREST).
revoke all on public.domain_analyses from anon, authenticated;

-- Aucune politique n'est créée volontairement.
-- Si un jour un tableau de bord doit lire ces données DEPUIS le navigateur,
-- il faudra ajouter une colonne user_id + une politique du type :
--   create policy "lecture de ses propres analyses"
--     on public.domain_analyses for select to authenticated
--     using (auth.uid() = user_id);
-- En l'état, tout passe par /api/history (serveur).

-- ---------------------------------------------------------------------------
-- 4. Vérifications à lancer APRÈS exécution (lecture seule)
-- ---------------------------------------------------------------------------
-- a) RLS activé ?
--    select relname, relrowsecurity from pg_class where relname = 'domain_analyses';
--    -- attendu : relrowsecurity = true
--
-- b) Politiques existantes (doit être vide) :
--    select policyname, roles, cmd from pg_policies where tablename = 'domain_analyses';
--
-- c) Privilèges des rôles exposés (doit être vide) :
--    select grantee, privilege_type from information_schema.role_table_grants
--     where table_name = 'domain_analyses' and grantee in ('anon', 'authenticated');
--
-- d) Test réel de non-exposition : depuis un terminal, avec une clé ANON
--    (jamais la clé secrète) :
--    curl "https://VOTRE-PROJET.supabase.co/rest/v1/domain_analyses?select=*" \
--         (ajoutez l'en-tête HTTP nommé apikey, avec votre clé anon publique)
--    (remplacez VOTRE-PROJET et VOTRE_CLE_ANON_PUBLIQUE ; la clé anon est publique)
--    -- attendu : AUCUNE ligne renvoyée. Deux réponses acceptables selon que le
--    --          rôle anon a conservé des privilèges ou non :
--    --            * "permission denied for table domain_analyses" (code 42501)  <- cas normal ici (revoke)
--    --            * []  (tableau vide)                                            <- si RLS seul bloque
--    --  Dans les deux cas : jamais de données. Une liste de lignes = problème.
--
-- ---------------------------------------------------------------------------
-- 5. Note RGPD (données personnelles)
--    La colonne `email` est une donnée personnelle. Prévoir une purge, par ex.
--    une fois par mois :  delete from public.domain_analyses
--                          where created_at < now() - interval '12 months';
-- ---------------------------------------------------------------------------
