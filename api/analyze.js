'use strict';
/**
 * Email Domain Security — POST /api/analyze
 *
 * Reçoit { "email": "contact@entreprise.com" }, extrait le domaine, interroge
 * les sources de sécurité, calcule le niveau de risque et enregistre le rapport
 * dans Supabase (côté serveur uniquement).
 *
 * GET /api/analyze            -> informations sur l'application (sources, version)
 * GET /api/analyze?email=...  -> même analyse que POST (pratique pour tester)
 *
 * Aucune clé n'est exposée : les secrets sont lus dans process.env (Vercel) et
 * la réponse ne les contient jamais. Le rapport est renvoyé même si
 * l'enregistrement Supabase échoue (champ `saved: false`).
 */

const {
  isValidEmail,
  extractDomain,
  collectSignals,
  domainExists
} = require('../lib/checks');
const { computeScore, SCORING_VERSION } = require('../lib/scoring');
const { saveAnalysis, supabaseConfig } = require('../lib/supabase');

const APP_NAME = 'Email Domain Security';
const APP_VERSION = '1.0';
const BASE_SOURCES = ['dns', 'rdap', 'blocklist', 'urlscan'];

/** Corps de requête : objet déjà parsé par Vercel, sinon flux/chaîne. */
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body.length) {
    try {
      return JSON.parse(req.body);
    } catch {
      return null;
    }
  }
  if (!req || typeof req[Symbol.asyncIterator] !== 'function') return null;
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 10000) break; // garde-fou
  }
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function infoPayload() {
  return {
    ok: true,
    app: APP_NAME,
    version: `${APP_NAME} ${APP_VERSION}`,
    scoringVersion: SCORING_VERSION,
    usage: 'POST /api/analyze  { "email": "contact@entreprise.com" }',
    sources: BASE_SOURCES,
    virustotal_enabled: Boolean(process.env.VIRUSTOTAL_API_KEY),
    supabase_enabled: supabaseConfig().configured
  };
}

/**
 * Analyse complète. Ne lève jamais d'exception.
 * @returns {Promise<{statusCode:number, body:object}>}
 */
async function runAnalysis(email, options = {}) {
  const startedAt = Date.now();
  const value = typeof email === 'string' ? email.trim() : '';

  // 1. Validation de l'email
  if (!isValidEmail(value)) {
    return {
      statusCode: 400,
      body: {
        ok: false,
        code: 'INVALID_EMAIL',
        error: 'Adresse email invalide. Format attendu : contact@entreprise.com',
        saved: false
      }
    };
  }

  // 2. Extraction automatique du domaine
  const domain = extractDomain(value);

  // 3. Collecte des signaux (sources en parallèle, dégradation propre)
  const collected = await collectSignals(domain, {
    virustotalKey: options.virustotalKey,
    offline: options.offline,
    timeout: options.timeout
  });

  // 4. Domaine inexistant -> rapport UNKNOWN, enregistré quand même, HTTP 404
  const exists = domainExists(collected.signals);
  let scored;
  let statusCode = 200;
  let code = null;

  if (exists === false) {
    scored = {
      score: null,
      risk: 'UNKNOWN',
      reputation: 'UNKNOWN',
      reasons: [
        {
          code: 'DOMAIN_NOT_FOUND',
          label: "Le domaine n'existe pas : aucune réponse DNS et aucune donnée d'enregistrement (RDAP) trouvée",
          points: 0
        }
      ],
      warnings: [],
      hardFail: false,
      scoringVersion: SCORING_VERSION
    };
    statusCode = 404;
    code = 'DOMAIN_NOT_FOUND';
  } else {
    // 5. Calcul du niveau de risque
    scored = computeScore(collected.signals);
  }

  const report = {
    email: value,
    domain,
    registeredDomain: collected.registeredDomain,
    reputation: scored.reputation,
    risk: scored.risk,
    riskScore: scored.score,
    reasons: scored.reasons,
    warnings: scored.warnings,
    hardFail: scored.hardFail,
    exists,
    signals: collected.signals,
    sources: collected.sources,
    checkedAt: collected.checkedAt,
    durationMs: Date.now() - startedAt,
    scoringVersion: SCORING_VERSION,
    appVersion: APP_VERSION
  };

  // 6. Sauvegarde Supabase (server-side). Un échec ne casse pas la réponse.
  const save = await saveAnalysis(
    {
      email: report.email,
      domain: report.domain,
      reputation: report.reputation,
      risk: report.risk,
      score: report.riskScore,
      reasons: report.reasons,
      signals: report.signals,
      sources: report.sources,
      durationMs: report.durationMs,
      scoringVersion: report.scoringVersion
    },
    { config: options.supabaseConfig }
  );

  return {
    statusCode,
    body: {
      ok: true,
      code,
      saved: save.saved,
      save_error: save.saved ? null : save.error,
      save_message: save.saved ? null : save.message || null,
      report
    }
  };
}

module.exports = async function handler(req, res) {
  if (typeof res.setHeader === 'function') {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
  }

  const method = (req.method || 'GET').toUpperCase();

  if (method === 'GET') {
    const query = req.query || {};
    const email = query.email;
    if (!email) return res.status(200).json(infoPayload());
    const result = await runAnalysis(String(email), buildOptions());
    return res.status(result.statusCode).json(result.body);
  }

  if (method !== 'POST') {
    return res.status(405).json({ ok: false, code: 'METHOD_NOT_ALLOWED', error: 'Méthode non supportée. Utilisez POST avec { "email": "..." }.' });
  }

  const body = await readBody(req);
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ ok: false, code: 'INVALID_BODY', error: 'Corps de requête JSON invalide. Attendu : { "email": "contact@entreprise.com" }', saved: false });
  }

  const result = await runAnalysis(body.email, buildOptions());
  return res.status(result.statusCode).json(result.body);
};

function buildOptions() {
  return {
    virustotalKey: process.env.VIRUSTOTAL_API_KEY || '',
    offline: process.env.EDS_OFFLINE === '1'
  };
}

// Exposé pour les tests locaux (node --test).
module.exports.runAnalysis = runAnalysis;
module.exports.infoPayload = infoPayload;
module.exports.readBody = readBody;
