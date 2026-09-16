'use strict';
/**
 * Email Domain Security — GET /api/history
 * Renvoie les analyses enregistrées, avec pagination, recherche, filtre et tri :
 *   ?limit=10&offset=0&q=google&risk=HIGH&sort=score&dir=desc
 * Lecture uniquement, côté serveur, avec la clé secrète : le navigateur n'a
 * jamais accès à la table directement (RLS fermé, voir sql/001_domain_analyses.sql).
 */

const { listAnalyses, supabaseConfig } = require('../lib/supabase');

module.exports = async function handler(req, res) {
  if (typeof res.setHeader === 'function') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
  }

  const method = (req.method || 'GET').toUpperCase();
  if (method !== 'GET') {
    return res.status(405).json({ ok: false, code: 'METHOD_NOT_ALLOWED', error: 'Cette route est en lecture seule (GET).' });
  }

  const query = req.query || {};
  const result = await listAnalyses({
    limit: query.limit,
    offset: query.offset,
    search: query.q || query.search,
    risk: query.risk,
    sort: query.sort,
    dir: query.dir,
    config: supabaseConfig()
  });

  return res.status(200).json({
    ok: result.ok,
    configured: result.configured,
    count: result.rows.length,
    total: result.ok ? result.total : 0,
    limit: result.limit,
    offset: result.offset,
    search: result.search || '',
    risk: result.risk || '',
    sort: result.sort || 'date',
    dir: result.dir || 'desc',
    error: result.error || null,
    message: result.message || null,
    rows: result.rows
  });
};

module.exports.listAnalyses = listAnalyses;
