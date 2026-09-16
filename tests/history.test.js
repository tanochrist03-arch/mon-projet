'use strict';
/**
 * Email Domain Security — tests de l'historique :
 * pagination, recherche, nettoyage du terme de recherche, gestion des erreurs.
 * Réseau entièrement simulé. Lancement : node --test
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { listAnalyses, sanitizeSearch } = require('../lib/supabase');
const historyHandler = require('../api/history.js');

const CONFIG = { url: 'https://exemple-test.supabase.co', key: 'sb_secret_CLE_FACTICE_TEST_0001', configured: true };

function fakeResponse(payload, { status = 200, contentRange = null } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => (String(name).toLowerCase() === 'content-range' ? contentRange : null) },
    json: async () => payload,
    text: async () => JSON.stringify(payload)
  };
}

function captureFetch(response) {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    return response;
  };
  return calls;
}

function fakeRes() {
  return {
    statusCode: null,
    payload: null,
    headers: {},
    status(code) { this.statusCode = code; return this; },
    setHeader(name, value) { this.headers[name] = value; return this; },
    json(payload) { this.payload = payload; return this; }
  };
}

/** L'endpoint lit la configuration dans process.env : on simule une config valide. */
async function withSupabaseEnv(fn) {
  const keys = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'SUPABASE_SERVICE_ROLE_KEY'];
  const saved = {};
  for (const key of keys) { saved[key] = process.env[key]; }
  process.env.SUPABASE_URL = CONFIG.url;
  process.env.SUPABASE_SECRET_KEY = CONFIG.key;
  delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  try {
    await fn();
  } finally {
    for (const key of keys) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

/* ----------------------------- nettoyage de la recherche ---------------- */

test('sanitizeSearch retire tout caractère dangereux pour PostgREST', () => {
  assert.equal(sanitizeSearch('google.com'), 'google.com');
  assert.equal(sanitizeSearch('contact@google.com'), 'contact@google.com');
  assert.equal(sanitizeSearch('  Google.COM  '), 'Google.COM');
  assert.equal(sanitizeSearch('*,domain.eq.admin'), 'domain.eq.admin');
  assert.equal(sanitizeSearch('a) or (b'), 'aorb');
  assert.equal(sanitizeSearch('%%%'), '');
  assert.equal(sanitizeSearch(null), '');
  assert.equal(sanitizeSearch(undefined), '');
  assert.equal(sanitizeSearch(42), '');
  assert.equal(sanitizeSearch('x'.repeat(500)).length, 100);
});

/* ----------------------------- requête vers PostgREST ------------------- */

test('listAnalyses construit la pagination, le tri et le filtre de recherche', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  await listAnalyses({ limit: 10, offset: 20, search: 'google', config: CONFIG });

  const url = calls[0].url;
  assert.match(url, /limit=10/);
  assert.match(url, /offset=20/);
  assert.match(url, /order=created_at\.desc/);
  assert.match(url, /or=%28domain\.ilike\.\*google\*%2Cemail\.ilike\.\*google\*%29/);
  assert.equal(calls[0].options.headers.Prefer, 'count=exact');
  assert.equal(calls[0].options.headers.apikey, CONFIG.key);
});

test('listAnalyses lit le total dans l’en-tête Content-Range', async () => {
  captureFetch(fakeResponse([{ id: 1 }, { id: 2 }], { contentRange: '10-11/57' }));
  const result = await listAnalyses({ limit: 2, offset: 10, config: CONFIG });
  assert.equal(result.ok, true);
  assert.equal(result.total, 57);
  assert.equal(result.rows.length, 2);
});

test('listAnalyses borne la taille de page entre 1 et 100', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  await listAnalyses({ limit: 5000, offset: -10, config: CONFIG });
  assert.match(calls[0].url, /limit=100/);
  assert.match(calls[0].url, /offset=0/);
});

test('une page au-delà du total (416) n’est pas une erreur', async () => {
  captureFetch(fakeResponse({}, { status: 416, contentRange: '*/12' }));
  const result = await listAnalyses({ limit: 10, offset: 100, config: CONFIG });
  assert.equal(result.ok, true);
  assert.deepEqual(result.rows, []);
  assert.equal(result.total, 12);
});

test('Supabase non configuré -> ok:false, configured:false, aucun appel réseau', async () => {
  let called = false;
  globalThis.fetch = async () => { called = true; return fakeResponse([]); };
  const result = await listAnalyses({ config: { url: '', key: '', configured: false } });
  assert.equal(result.ok, false);
  assert.equal(result.configured, false);
  assert.equal(result.error, 'not_configured');
  assert.equal(called, false);
});

test('erreur Supabase -> message nettoyé, la clé n’apparaît jamais', async () => {
  captureFetch(fakeResponse({ message: 'Invalid API key' }, { status: 401 }));
  const result = await listAnalyses({ config: CONFIG });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'supabase_401');
  assert.equal(JSON.stringify(result).includes(CONFIG.key), false);
  assert.equal(JSON.stringify(result).includes('exemple-test.supabase.co'), false);
});

/* ----------------------------- endpoint /api/history -------------------- */

test('GET /api/history renvoie la structure attendue par l’interface', async () => {
  await withSupabaseEnv(async () => {
  captureFetch(
    fakeResponse(
      [
        { id: 'a', created_at: '2026-09-16T11:32:28Z', email: 'contact@google.com', domain: 'google.com', reputation: 'GOOD', risk: 'LOW', risk_score: 5, reasons: [], sources: ['dns'], duration_ms: 900 }
      ],
      { contentRange: '0-0/1' }
    )
  );
  const res = fakeRes();
  await historyHandler({ method: 'GET', query: { limit: '10', offset: '0' } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.ok, true);
  assert.equal(res.payload.configured, true);
  assert.equal(res.payload.count, 1);
  assert.equal(res.payload.total, 1);
  assert.equal(res.payload.limit, 10);
  assert.equal(res.payload.offset, 0);
  assert.equal(res.payload.search, '');
  assert.equal(res.payload.rows[0].domain, 'google.com');
  });
});

test('GET /api/history transmet la recherche (?q=) après nettoyage', async () => {
  await withSupabaseEnv(async () => {
    const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
    const res = fakeRes();
    await historyHandler({ method: 'GET', query: { q: 'g<o>o)gle' } }, res);
    assert.match(calls[0].url, /ilike/);
    assert.equal(res.payload.search, 'google');
  });
});

test('POST /api/history -> 405 (lecture seule)', async () => {
  const res = fakeRes();
  await historyHandler({ method: 'POST', query: {}, body: {} }, res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.payload.code, 'METHOD_NOT_ALLOWED');
});

test('l’historique n’expose ni clé ni URL Supabase', async () => {
  await withSupabaseEnv(async () => {
    captureFetch(fakeResponse([{ id: 'a', domain: 'google.com' }], { contentRange: '0-0/1' }));
    const res = fakeRes();
    await historyHandler({ method: 'GET', query: {} }, res);
    const serialized = JSON.stringify(res.payload);
    assert.equal(serialized.includes(CONFIG.key), false);
    assert.equal(serialized.includes('supabase.co'), false);
  });
});

/* ----------------------------- filtre par risque ------------------------ */

test('le filtre de risque devient risk=eq.XXX dans la requête PostgREST', async () => {
  const calls = captureFetch(fakeResponse([{ id: 'a', risk: 'HIGH' }], { contentRange: '0-0/1' }));
  const result = await listAnalyses({ risk: 'HIGH', config: CONFIG });
  assert.match(calls[0].url, /risk=eq\.HIGH/);
  assert.equal(result.risk, 'HIGH');
});

test('le filtre de risque tolère la casse et les espaces', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  const result = await listAnalyses({ risk: '  low ', config: CONFIG });
  assert.match(calls[0].url, /risk=eq\.LOW/);
  assert.equal(result.risk, 'LOW');
});

test('un niveau de risque inconnu est ignoré : aucun filtre, aucune injection', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  const result = await listAnalyses({ risk: "LOW' OR 1=1--", config: CONFIG });
  assert.equal(/risk=/.test(calls[0].url), false);
  assert.equal(result.risk, '');
});

test('le niveau UNKNOWN est un filtre légitime', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  const result = await listAnalyses({ risk: 'unknown', config: CONFIG });
  assert.match(calls[0].url, /risk=eq\.UNKNOWN/);
  assert.equal(result.risk, 'UNKNOWN');
});

/* ----------------------------- tri -------------------------------------- */

test('tri par score décroissant : risk_score + nulls last', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  const result = await listAnalyses({ sort: 'score', dir: 'desc', config: CONFIG });
  assert.match(calls[0].url, /order=risk_score\.desc\.nullslast/);
  assert.equal(result.sort, 'score');
  assert.equal(result.dir, 'desc');
});

test('tri par score croissant', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  await listAnalyses({ sort: 'score', dir: 'asc', config: CONFIG });
  assert.match(calls[0].url, /order=risk_score\.asc\.nullslast/);
});

test('tri par date croissante', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  await listAnalyses({ sort: 'date', dir: 'asc', config: CONFIG });
  assert.match(calls[0].url, /order=created_at\.asc/);
});

test('une colonne de tri inconnue retombe sur le tri par défaut, sans injection', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  const result = await listAnalyses({ sort: 'created_at;DROP TABLE', dir: 'desc', config: CONFIG });
  assert.match(calls[0].url, /order=created_at\.desc/);
  assert.equal(calls[0].url.includes('DROP'), false);
  assert.equal(result.sort, 'date');
});

test('le tri par défaut reste les analyses les plus récentes', async () => {
  const calls = captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
  const result = await listAnalyses({ config: CONFIG });
  assert.match(calls[0].url, /order=created_at\.desc/);
  assert.equal(result.sort, 'date');
  assert.equal(result.dir, 'desc');
});

/* ----------------------------- endpoint : filtres ----------------------- */

test('GET /api/history expose le filtre et le tri appliqués', async () => {
  await withSupabaseEnv(async () => {
    const calls = captureFetch(fakeResponse([{ id: 'a', risk: 'HIGH', domain: 'yopmail.com' }], { contentRange: '0-0/1' }));
    const res = fakeRes();
    await historyHandler({ method: 'GET', query: { q: 'yopmail', risk: 'HIGH', sort: 'score', dir: 'desc' } }, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.payload.risk, 'HIGH');
    assert.equal(res.payload.sort, 'score');
    assert.equal(res.payload.dir, 'desc');
    assert.equal(res.payload.search, 'yopmail');
    const url = decodeURIComponent(calls[0].url);
    assert.match(url, /risk=eq\.HIGH/);
    assert.match(url, /order=risk_score\.desc\.nullslast/);
    assert.match(url, /ilike\.\*yopmail\*/);
  });
});

test('GET /api/history sans filtre : valeurs par défaut stables', async () => {
  await withSupabaseEnv(async () => {
    captureFetch(fakeResponse([], { contentRange: '0-0/0' }));
    const res = fakeRes();
    await historyHandler({ method: 'GET', query: {} }, res);
    assert.equal(res.payload.risk, '');
    assert.equal(res.payload.sort, 'date');
    assert.equal(res.payload.dir, 'desc');
  });
});
