'use strict';
/**
 * Email Domain Security — tests de l'endpoint /api/analyze (réseau entièrement simulé).
 * Lancement : node --test tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const handler = require('../api/analyze.js');

/* ----------------------------- outillage -------------------------------- */

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

function jsonResponse(payload, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(payload) };
}

function dnsOk(overrides = {}) {
  const mx = overrides.mx || [{ name: 'd.com.', type: 15, TTL: 300, data: '10 mx1.d.com.' }];
  const txt = overrides.txt || [{ name: 'd.com.', type: 16, TTL: 300, data: '"v=spf1 -all"' }];
  const dmarc = overrides.dmarc || [{ name: '_dmarc.d.com.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }];
  const a = overrides.a || [{ name: 'd.com.', type: 1, TTL: 60, data: '203.0.113.1' }];
  const ns = overrides.ns || [{ name: 'd.com.', type: 2, TTL: 300, data: 'ns1.d.com.' }];
  return (url) => {
    if (url.includes('type=MX')) return jsonResponse({ Status: 0, Answer: mx });
    if (url.includes('_dmarc.')) return jsonResponse({ Status: 0, Answer: dmarc });
    if (url.includes('type=TXT')) return jsonResponse({ Status: 0, Answer: txt });
    if (url.includes('type=NS')) return jsonResponse({ Status: 0, Answer: ns });
    if (url.includes('type=A')) return jsonResponse({ Status: 0, Answer: a });
    return jsonResponse({ Status: 0, Answer: [] });
  };
}

/** Installe un faux réseau : DNS, RDAP, urlscan, liste de jetables, Supabase. */
function installNetwork(options = {}) {
  const okStatus = options.dnsStatus || 0;
  globalThis.fetch = async (url) => {
    const target = String(url);
    if (target.includes('dns.google')) {
      if (options.dnsDown) {
        const err = new Error('aborted');
        err.name = 'AbortError';
        throw err;
      }
      if (options.nxdomain) return jsonResponse({ Status: 3, Answer: [] });
      return dnsOk(options.dns)(target);
    }
    if (target.includes('rdap.org')) {
      if (options.rdapDown) {
        const err = new Error('aborted');
        err.name = 'AbortError';
        throw err;
      }
      if (options.rdapNotFound) return jsonResponse({ errorCode: 404 }, 404);
      return jsonResponse({
        ldhName: 'D.COM',
        events: [{ eventAction: 'registration', eventDate: options.createdAt || '2012-03-04T00:00:00Z' }],
        entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Registrar de test']]] }]
      });
    }
    if (target.includes('urlscan.io')) return jsonResponse({ total: 0, results: [] });
    if (target.includes('raw.githubusercontent.com')) return jsonResponse({}, 500); // force la liste locale
    if (target.includes('supabase.co')) {
      if (options.supabaseStatus) return jsonResponse({ message: options.supabaseMessage || 'erreur simulée' }, options.supabaseStatus);
      return jsonResponse({}, 201);
    }
    throw new Error(`fetch inattendu : ${target}`);
  };
}

const ENV_KEYS = ['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'VIRUSTOTAL_API_KEY', 'EDS_OFFLINE'];

function withEnv(values, fn) {
  return async () => {
    const saved = {};
    for (const key of ENV_KEYS) saved[key] = process.env[key];
    for (const key of ENV_KEYS) delete process.env[key];
    Object.assign(process.env, values);
    try {
      await fn();
    } finally {
      for (const key of ENV_KEYS) {
        if (saved[key] === undefined) delete process.env[key];
        else process.env[key] = saved[key];
      }
    }
  };
}

/* ----------------------------- tests ------------------------------------ */

test('GET sans email -> informations sur l’application', async () => {
  process.env.EDS_OFFLINE = '1';
  const res = fakeRes();
  await handler({ method: 'GET', query: {} }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.ok, true);
  assert.deepEqual(res.payload.sources, ['dns', 'rdap', 'blocklist', 'urlscan']);
  assert.equal(res.payload.virustotal_enabled, false);
  assert.equal(res.statusCode, 200);
});

test('méthode non supportée -> 405', async () => {
  const res = fakeRes();
  await handler({ method: 'PUT', query: {}, body: {} }, res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.payload.code, 'METHOD_NOT_ALLOWED');
});

test('email invalide -> 400 INVALID_EMAIL', async () => {
  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: { email: 'pas-un-email' } }, res);
  assert.equal(res.statusCode, 400);
  assert.equal(res.payload.code, 'INVALID_EMAIL');
  assert.equal(res.payload.saved, false);
});

test('corps invalide -> 400 INVALID_BODY', async () => {
  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: null }, res);
  assert.equal(res.statusCode, 400);
  assert.equal(res.payload.code, 'INVALID_BODY');
});

test('domaine propre -> 200, LOW, GOOD, avec extraction du domaine', withEnv({ EDS_OFFLINE: '1' }, async () => {
  installNetwork();
  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: { email: 'Contact@Entreprise.COM' } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.report.domain, 'entreprise.com');
  assert.equal(res.payload.report.risk, 'LOW');
  assert.equal(res.payload.report.reputation, 'GOOD');
  assert.equal(res.payload.report.riskScore, 0);
  // Sans Supabase configuré : le rapport est renvoyé, l'enregistrement est signalé
  assert.equal(res.payload.saved, false);
  assert.equal(res.payload.save_error, 'not_configured');
  assert.ok(res.payload.report.reasons.length === 0);
}));

test('domaine jetable -> HIGH + MALICIOUS', withEnv({ EDS_OFFLINE: '1' }, async () => {
  installNetwork();
  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: { email: 'test@yopmail.com' } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.report.risk, 'HIGH');
  assert.equal(res.payload.report.reputation, 'MALICIOUS');
  assert.equal(res.payload.report.reasons[0].code, 'DISPOSABLE_LISTED');
}));

test('domaine inexistant -> 404 DOMAIN_NOT_FOUND, risque UNKNOWN, analyse enregistrée quand même', withEnv({ EDS_OFFLINE: '1' }, async () => {
  installNetwork({ nxdomain: true, rdapNotFound: true });
  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: { email: 'contact@domaine-inexistant-xyz.tld' } }, res);

  assert.equal(res.statusCode, 404);
  assert.equal(res.payload.code, 'DOMAIN_NOT_FOUND');
  assert.equal(res.payload.report.risk, 'UNKNOWN');
  assert.equal(res.payload.report.reputation, 'UNKNOWN');
  assert.equal(res.payload.report.riskScore, null);
  assert.equal(res.payload.report.exists, false);
}));

test('toutes les sources en panne -> 200, aucun plantage, réputation UNKNOWN', withEnv({ EDS_OFFLINE: '1' }, async () => {
  installNetwork({ dnsDown: true, rdapDown: true });
  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: { email: 'contact@entreprise.com' } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.ok, true);
  assert.equal(res.payload.report.reputation, 'UNKNOWN');
  assert.equal(res.payload.report.sources.dns, 'error');
  assert.equal(res.payload.report.warnings.length, 1);
}));

test('VirusTotal activé uniquement si une clé est fournie', withEnv({ EDS_OFFLINE: '1', VIRUSTOTAL_API_KEY: 'CLE_TEST' }, async () => {
  let calledVt = false;
  installNetwork();
  const base = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    if (String(url).includes('virustotal.com')) {
      calledVt = true;
      assert.equal(opts.headers['x-apikey'], 'CLE_TEST');
      return jsonResponse({ data: { attributes: { last_analysis_stats: { malicious: 4, suspicious: 0, harmless: 60, undetected: 3 }, categories: {} } } });
    }
    return base(url, opts);
  };

  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: { email: 'contact@entreprise.com' } }, res);
  assert.equal(calledVt, true);
  assert.equal(res.payload.report.reputation, 'MALICIOUS');
  assert.equal(res.payload.report.risk, 'HIGH');
}));

test('Supabase en erreur -> rapport renvoyé, saved=false, clé jamais exposée', withEnv(
  { EDS_OFFLINE: '1', SUPABASE_URL: 'https://exemple-test.supabase.co', SUPABASE_SECRET_KEY: 'sb_secret_CLE_FACTICE_TEST_0001' },
  async () => {
    installNetwork({ supabaseStatus: 401, supabaseMessage: 'Invalid API key' });
    const res = fakeRes();
    await handler({ method: 'POST', query: {}, body: { email: 'contact@entreprise.com' } }, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.payload.saved, false);
    assert.equal(res.payload.save_error, 'supabase_401');
    const serialized = JSON.stringify(res.payload);
    assert.equal(serialized.includes('sb_secret_CLE_FACTICE_TEST_0001'), false, 'la clé secrète ne doit jamais apparaître dans la réponse');
    assert.equal(serialized.includes('exemple-test.supabase.co'), false, 'l’URL Supabase ne doit pas être exposée');
  }
));

test('Supabase configuré et disponible -> saved=true', withEnv(
  { EDS_OFFLINE: '1', SUPABASE_URL: 'https://exemple-test.supabase.co', SUPABASE_SECRET_KEY: 'sb_secret_CLE_FACTICE_TEST_0001' },
  async () => {
    installNetwork();
    const res = fakeRes();
    await handler({ method: 'POST', query: {}, body: { email: 'contact@entreprise.com' } }, res);
    assert.equal(res.payload.saved, true);
    assert.equal(res.payload.save_error, null);
  }
));

test('GET ?email=... fonctionne comme POST (test manuel rapide)', withEnv({ EDS_OFFLINE: '1' }, async () => {
  installNetwork();
  const res = fakeRes();
  await handler({ method: 'GET', query: { email: 'contact@entreprise.com' } }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.payload.report.domain, 'entreprise.com');
}));

test('la réponse ne contient jamais de motif de secret', withEnv({ EDS_OFFLINE: '1' }, async () => {
  installNetwork();
  const res = fakeRes();
  await handler({ method: 'POST', query: {}, body: { email: 'contact@entreprise.com' } }, res);
  const serialized = JSON.stringify(res.payload);
  for (const pattern of [/sb_secret_/, /sb_publishable_/, /sk-[A-Za-z0-9]{20,}/, /bot\d{8,}:/]) {
    assert.equal(pattern.test(serialized), false, `motif interdit détecté : ${pattern}`);
  }
}));
