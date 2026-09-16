'use strict';
/**
 * Email Domain Security — test de contrat entre le schéma SQL et le code JavaScript.
 * Vérifie AVANT exécution que ce que le code envoie à Supabase correspond
 * exactement à ce que le script SQL crée, et que le durcissement RLS est bien
 * présent dans le script (RLS activé, aucune politique publique).
 * Lancement : node --test
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { toRow } = require('../lib/supabase');
const { RISK_LEVELS, REPUTATIONS } = require('../lib/scoring');

const SQL_FILE = path.join(__dirname, '..', 'sql', '001_domain_analyses.sql');
const rawSql = fs.readFileSync(SQL_FILE, 'utf8');

/** SQL sans les commentaires : ce qui sera réellement exécuté. */
const sql = rawSql
  .split(/\r?\n/)
  .filter((line) => !line.trim().startsWith('--'))
  .join('\n');

/** Colonnes déclarées dans la table. */
function tableColumns() {
  const block = /create table if not exists public\.domain_analyses \(([\s\S]*?)\n\);/i.exec(sql);
  assert.ok(block, 'bloc create table introuvable dans le script SQL');
  return block[1]
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => line.split(/\s+/)[0].replace(/,$/, ''))
    .filter(Boolean);
}

/** Exemple de rapport, calqué sur ce que produit api/analyze.js. */
function sampleRecord() {
  return {
    email: 'contact@entreprise.com',
    domain: 'entreprise.com',
    reputation: 'GOOD',
    risk: 'LOW',
    score: 12,
    reasons: [{ code: 'SPF_SOFTFAIL', label: 'SPF réglé sur ~all', points: 5 }],
    signals: { dns: { hasMx: true, spf: 'v=spf1 -all' }, rdap: { found: true, ageDays: 4000 } },
    sources: { dns: 'ok', rdap: 'ok', blocklist: 'ok', urlscan: 'error', virustotal: 'disabled' },
    durationMs: 850,
    scoringVersion: 'email-domain-security-1.0'
  };
}

test('chaque champ envoyé par le code existe dans la table SQL', () => {
  const columns = tableColumns();
  const sent = Object.keys(toRow(sampleRecord()));
  const missing = sent.filter((field) => !columns.includes(field));
  assert.deepEqual(missing, [], `colonnes absentes du SQL : ${missing.join(', ')}`);
});

test('la table n’exige aucun champ que le code n’envoie pas', () => {
  const columns = tableColumns();
  const sent = Object.keys(toRow(sampleRecord()));
  // id et created_at sont générés par PostgreSQL (default), les autres doivent venir du code.
  const generated = ['id', 'created_at'];
  const required = columns.filter((c) => !generated.includes(c));
  const unexpected = required.filter((c) => !sent.includes(c));
  assert.deepEqual(unexpected, [], `colonnes non renseignées par le code : ${unexpected.join(', ')}`);
});

test('colonnes et types attendus présents', () => {
  const columns = tableColumns();
  const expected = [
    'id', 'created_at', 'email', 'domain', 'reputation', 'risk',
    'risk_score', 'reasons', 'signals', 'sources', 'duration_ms', 'app_version'
  ];
  for (const column of expected) {
    assert.ok(columns.includes(column), `colonne manquante : ${column}`);
  }
  assert.match(sql, /id\s+uuid primary key/i);
  assert.match(sql, /created_at\s+timestamptz not null default now\(\)/i);
  assert.match(sql, /reasons\s+jsonb/i);
  assert.match(sql, /signals\s+jsonb/i);
  assert.match(sql, /sources\s+text\[\]/i);
  assert.match(sql, /duration_ms\s+integer/i);
});

test('risk_score est nullable (cas « domaine inexistant »)', () => {
  assert.match(sql, /risk_score\s+integer\s+check/i);
  assert.equal(/risk_score\s+integer not null/i.test(sql), false, 'risk_score ne doit pas être NOT NULL');
  assert.match(sql, /risk_score is null or \(risk_score between 0 and 100\)/i);
});

test('les contraintes de valeurs couvrent tout ce que le code peut produire', () => {
  // risk : LOW / MEDIUM / HIGH produits par scoring.js + UNKNOWN (domaine inexistant)
  for (const level of [...RISK_LEVELS, 'UNKNOWN']) {
    assert.match(sql, new RegExp(`risk in \\([^)]*'${level}'`, 'i'), `valeur de risque absente du CHECK : ${level}`);
  }
  for (const reputation of REPUTATIONS) {
    assert.match(sql, new RegExp(`reputation in \\([^)]*'${reputation}'`, 'i'), `réputation absente du CHECK : ${reputation}`);
  }
});

test('index attendus déclarés', () => {
  assert.match(sql, /create index if not exists domain_analyses_domain_idx\s+on public\.domain_analyses \(domain\)/i);
  assert.match(sql, /create index if not exists domain_analyses_created_at_idx\s+on public\.domain_analyses \(created_at desc\)/i);
  assert.match(sql, /create index if not exists domain_analyses_risk_idx\s+on public\.domain_analyses \(risk\)/i);
});

test('durcissement RLS présent et aucune politique publique active', () => {
  assert.match(sql, /alter table public\.domain_analyses enable row level security/i, 'RLS doit être activé');
  assert.match(sql, /revoke all on public\.domain_analyses from anon, authenticated/i, 'les droits anon/authenticated doivent être retirés');
  // Une "create policy" active (hors commentaire) ouvrirait la table : interdit ici.
  assert.equal(/create\s+policy/i.test(sql), false, 'aucune politique ne doit être créée par ce script');
  assert.equal(/disable row level security/i.test(sql), false);
  assert.equal(/drop\s+table/i.test(sql), false, 'le script ne doit supprimer aucune table');
  assert.equal(/delete\s+from/i.test(sql), false, 'le script ne doit supprimer aucune donnée');
  assert.equal(/truncate|drop\s+column/i.test(sql), false);
});

test('le script est idempotent (rejouable sans erreur)', () => {
  for (const statement of ['create table', 'create index']) {
    const occurrences = (sql.match(new RegExp(statement, 'gi')) || []).length;
    const guarded = (sql.match(new RegExp(`${statement} if not exists`, 'gi')) || []).length;
    assert.equal(occurrences, guarded, `« ${statement} » doit toujours être protégé par « if not exists »`);
  }
});

test('les données envoyées sont sérialisables telles quelles par PostgREST', () => {
  const row = toRow(sampleRecord());
  const payload = JSON.stringify(row);
  assert.ok(payload.length > 0);
  const parsed = JSON.parse(payload);
  assert.ok(Array.isArray(parsed.reasons), 'reasons doit être un tableau JSON (jsonb)');
  assert.equal(typeof parsed.signals, 'object');
  assert.ok(Array.isArray(parsed.sources), 'sources doit être un tableau (text[])');
  assert.ok(parsed.sources.every((s) => typeof s === 'string'));
  assert.equal(parsed.risk_score, 12);
  assert.equal(parsed.app_version, 'email-domain-security-1.0');
});

test('risk_score vaut null (et non 0) quand aucun score n’est calculable', () => {
  const row = toRow({ ...sampleRecord(), score: null, risk: 'UNKNOWN', reputation: 'UNKNOWN' });
  assert.equal(row.risk_score, null);
  assert.equal(JSON.parse(JSON.stringify(row)).risk_score, null);
});

test('le script SQL ne contient aucune clé ni URL de projet', () => {
  assert.equal(/sb_secret_|sb_publishable_|eyJ[A-Za-z0-9_-]{20}/.test(rawSql), false);
  assert.equal(/[a-z0-9]{20}\.supabase\.co/.test(rawSql), false);
});
