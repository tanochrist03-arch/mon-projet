'use strict';
/**
 * Email Domain Security — Accès Supabase, CÔTÉ SERVEUR UNIQUEMENT.
 *
 * Règles appliquées :
 *  - la clé n'est jamais écrite dans le code : elle est lue dans process.env
 *    (variables Vercel) et passée en paramètre ;
 *  - elle n'apparaît jamais dans un log ni dans un message d'erreur
 *    (fonction `sanitize`) ;
 *  - aucune dépendance : on parle directement à PostgREST en HTTPS.
 */

const DEFAULT_TIMEOUT = 8000;
const TABLE = 'domain_analyses';

/** Lit la configuration Supabase depuis l'environnement. */
function supabaseConfig(env = process.env) {
  const url = (env.SUPABASE_URL || '').replace(/\/+$/, '');
  const key = env.SUPABASE_SECRET_KEY || env.SUPABASE_SERVICE_ROLE_KEY || '';
  return { url, key, configured: Boolean(url && key) };
}

/** Retire toute trace de secret d'un texte destiné aux logs / réponses. */
function sanitize(text, key) {
  if (typeof text !== 'string') return text;
  let out = text;
  if (key && key.length > 8) out = out.split(key).join('***');
  return out.slice(0, 500);
}

/** Convertit un rapport d'analyse en ligne de table. */
function toRow(record) {
  return {
    email: record.email,
    domain: record.domain,
    reputation: record.reputation,
    risk: record.risk,
    risk_score: typeof record.score === 'number' ? record.score : null,
    reasons: record.reasons || [],
    signals: record.signals || {},
    sources: record.sources ? Object.keys(record.sources) : [],
    duration_ms: typeof record.durationMs === 'number' ? record.durationMs : null,
    app_version: record.scoringVersion || null
  };
}

async function request(url, options, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Enregistre une analyse. Ne lève JAMAIS d'exception : renvoie toujours un objet
 * { saved, error? } pour que l'application continue de fonctionner même si
 * Supabase est mal configuré ou indisponible.
 */
async function saveAnalysis(record, options = {}) {
  const { url, key, configured } = options.config || supabaseConfig();
  if (!configured) {
    return { saved: false, error: 'not_configured', message: 'Supabase non configuré (SUPABASE_URL / SUPABASE_SECRET_KEY absents).' };
  }

  const endpoint = `${url}/rest/v1/${options.table || TABLE}`;
  try {
    const res = await request(
      endpoint,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          apikey: key,
          Authorization: `Bearer ${key}`,
          Prefer: 'return=minimal'
        },
        body: JSON.stringify(toRow(record))
      },
      options.timeout || DEFAULT_TIMEOUT
    );

    if (res.status === 201 || res.status === 204 || res.ok) return { saved: true };
    const detail = sanitize(await safeText(res), key);
    return { saved: false, error: `supabase_${res.status}`, message: detail };
  } catch (err) {
    return {
      saved: false,
      error: err && err.name === 'AbortError' ? 'supabase_timeout' : 'supabase_unreachable',
      message: sanitize(err && err.message ? err.message : String(err), key)
    };
  }
}

/** Nettoie un terme de recherche : caractères sûrs uniquement (pas d'injection PostgREST). */
function sanitizeSearch(value) {
  if (typeof value !== 'string') return '';
  return value
    .trim()
    .slice(0, 100)
    .replace(/[^A-Za-z0-9@._-]/g, '');
}

/** Niveaux de risque acceptés pour le filtre d'historique. */
const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'UNKNOWN'];

/** Colonnes de tri autorisées — liste blanche, jamais de valeur venue du client. */
const SORT_COLUMNS = {
  date: 'created_at',
  score: 'risk_score',
  domain: 'domain',
  reputation: 'reputation',
  risk: 'risk'
};

/** Valide le filtre de risque : '' (aucun) ou LOW|MEDIUM|HIGH|UNKNOWN. */
function normalizeRisk(value) {
  const risk = String(value || '').trim().toUpperCase();
  return RISK_LEVELS.indexOf(risk) === -1 ? '' : risk;
}

/** Valide le tri : { column, direction } sans jamais refléter une entrée arbitraire. */
function normalizeSort(sort, dir) {
  const key = String(sort || '').trim().toLowerCase();
  const column = SORT_COLUMNS[key] || SORT_COLUMNS.date;
  const direction = String(dir || '').trim().toLowerCase() === 'asc' ? 'asc' : 'desc';
  return { sort: SORT_COLUMNS[key] ? key : 'date', column, dir: direction };
}

/**
 * Analyses enregistrées, avec pagination, recherche, filtre et tri.
 * @param {{limit?:number, offset?:number, search?:string, risk?:string,
 *          sort?:string, dir?:string, config?:object, table?:string}} options
 * @returns {Promise<{ok:boolean, configured:boolean, rows:Array, total:number,
 *                    limit:number, offset:number, search:string, risk:string,
 *                    sort:string, dir:string, error?:string, message?:string}>}
 */
async function listAnalyses(options = {}) {
  const { url, key, configured } = options.config || supabaseConfig();
  const limit = Math.min(Math.max(parseInt(options.limit, 10) || 20, 1), 100);
  const offset = Math.max(parseInt(options.offset, 10) || 0, 0);
  const search = sanitizeSearch(options.search);
  const risk = normalizeRisk(options.risk);
  const ordering = normalizeSort(options.sort, options.dir);

  if (!configured) {
    return { ok: false, configured: false, rows: [], total: 0, limit, offset, search, risk, sort: ordering.sort, dir: ordering.dir, error: 'not_configured' };
  }

  const params = new URLSearchParams();
  params.set('select', 'id,created_at,email,domain,reputation,risk,risk_score,reasons,sources,duration_ms,app_version');
  params.set('order', ordering.column === 'risk_score'
    ? `${ordering.column}.${ordering.dir}.nullslast`
    : `${ordering.column}.${ordering.dir}`);
  params.set('limit', String(limit));
  params.set('offset', String(offset));
  if (search) params.set('or', `(domain.ilike.*${search}*,email.ilike.*${search}*)`);
  if (risk) params.set('risk', `eq.${risk}`);

  const endpoint = `${url}/rest/v1/${options.table || TABLE}?${params.toString()}`;
  try {
    const res = await request(
      endpoint,
      {
        method: 'GET',
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
          Accept: 'application/json',
          Prefer: 'count=exact'
        }
      },
      options.timeout || DEFAULT_TIMEOUT
    );

    // PostgREST renvoie le total dans l'en-tête Content-Range : "0-9/123"
    const range = res.headers && typeof res.headers.get === 'function' ? res.headers.get('content-range') : null;
    let total = null;
    if (range && range.includes('/')) {
      const rawTotal = range.split('/')[1];
      if (rawTotal && rawTotal !== '*') total = parseInt(rawTotal, 10);
    }

    // 416 = page au-delà du total : ce n'est pas une erreur, la liste est vide.
    if (res.status === 416) {
      return { ok: true, configured: true, rows: [], total: total === null ? 0 : total, limit, offset, search, risk, sort: ordering.sort, dir: ordering.dir };
    }

    if (!res.ok) {
      return {
        ok: false,
        configured: true,
        rows: [],
        total: 0,
        limit,
        offset,
        search,
        risk,
        sort: ordering.sort,
        dir: ordering.dir,
        error: `supabase_${res.status}`,
        message: sanitize(await safeText(res), key)
      };
    }

    const rows = await res.json();
    const list = Array.isArray(rows) ? rows : [];
    return {
      ok: true,
      configured: true,
      rows: list,
      total: total === null ? list.length : total,
      limit,
      offset,
      search,
      risk,
      sort: ordering.sort,
      dir: ordering.dir
    };
  } catch (err) {
    return {
      ok: false,
      configured: true,
      rows: [],
      total: 0,
      limit,
      offset,
      search,
      risk,
      sort: ordering.sort,
      dir: ordering.dir,
      error: err && err.name === 'AbortError' ? 'supabase_timeout' : 'supabase_unreachable',
      message: sanitize(err && err.message ? err.message : String(err), key)
    };
  }
}

async function safeText(res) {
  try {
    return await res.text();
  } catch {
    return '';
  }
}

module.exports = { supabaseConfig, sanitize, sanitizeSearch, normalizeRisk, normalizeSort, toRow, saveAnalysis, listAnalyses, TABLE };
