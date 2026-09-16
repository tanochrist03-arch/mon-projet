'use strict';
/**
 * Email Domain Security — GET /api/history
 * Renvoie les analyses enregistrées, avec pagination et recherche :
 *   ?limit=10&offset=0&q=google
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
    error: result.error || null,
    message: result.message || null,
    rows: result.rows
  });
};

module.exports.listAnalyses = listAnalyses;
