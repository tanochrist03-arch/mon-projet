'use strict';
/**
 * Email Domain Security — tests des sources de collecte.
 * Toutes les requêtes réseau sont simulées : aucun appel sortant, résultat déterministe.
 * Lancement : node --test tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const checks = require('../lib/checks');

/* ----------------------------- utilitaires de mock ---------------------- */

function jsonResponse(payload, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(payload) };
}

/** Installe un faux fetch : la première route dont le motif est contenu dans l'URL répond. */
function mockFetch(routes) {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    for (const [pattern, responder] of routes) {
      if (String(url).includes(pattern)) return responder(String(url), options);
    }
    throw new Error(`fetch inattendu : ${url}`);
  };
  return calls;
}

function dnsAnswers(records) {
  return jsonResponse({ Status: 0, Answer: records });
}
function nxdomain() {
  return jsonResponse({ Status: 3 });
}

/* ----------------------------- validation / extraction ------------------ */

test('isValidEmail accepte les adresses correctes', () => {
  for (const email of ['contact@entreprise.com', 'a.b+tag@sous.domaine.fr', 'x_y@exemple-groupe.co.uk']) {
    assert.equal(checks.isValidEmail(email), true, email);
  }
});

test('isValidEmail rejette les adresses invalides', () => {
  for (const email of [
    'contact', 'contact@', '@entreprise.com', 'contact@entreprise', 'con..tact@entreprise.com',
    'contact@127.0.0.1', 'contact@entreprise.123', 'contact entreprise.com', '', null, undefined,
    'contact@-entreprise.com', 'a@b.c'
  ]) {
    assert.equal(checks.isValidEmail(email), false, String(email));
  }
});

test('extractDomain normalise la casse et les points finaux', () => {
  assert.equal(checks.extractDomain('Contact@Entreprise.COM'), 'entreprise.com');
  assert.equal(checks.extractDomain('contact@entreprise.com.'), 'entreprise.com');
  assert.equal(checks.extractDomain('contact@mail.entreprise.com'), 'mail.entreprise.com');
  assert.equal(checks.extractDomain('pas-un-email'), null);
});

test('registeredDomain réduit les sous-domaines mais respecte les extensions à deux niveaux', () => {
  assert.equal(checks.registeredDomain('mail.entreprise.com'), 'entreprise.com');
  assert.equal(checks.registeredDomain('entreprise.com'), 'entreprise.com');
  assert.equal(checks.registeredDomain('a.b.c.entreprise.com'), 'entreprise.com');
  assert.equal(checks.registeredDomain('mon-entreprise.co.uk'), 'mon-entreprise.co.uk');
  assert.equal(checks.registeredDomain('mail.mon-entreprise.co.uk'), 'mon-entreprise.co.uk');
});

/* ----------------------------- DNS -------------------------------------- */

test('checkDns interprète MX, SPF, DMARC, A et NS', async () => {
  mockFetch([
    ['dns.google', (url) => {
      if (url.includes('type=MX')) return dnsAnswers([{ name: 'entreprise.com.', type: 15, TTL: 300, data: '10 mx1.entreprise.com.' }]);
      if (url.includes('_dmarc.')) return dnsAnswers([{ name: '_dmarc.entreprise.com.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject; rua=mailto:dmarc@entreprise.com"' }]);
      if (url.includes('type=TXT')) return dnsAnswers([{ name: 'entreprise.com.', type: 16, TTL: 300, data: '"v=spf1 include:_spf.entreprise.com ~all"' }]);
      if (url.includes('type=NS')) return dnsAnswers([{ name: 'entreprise.com.', type: 2, TTL: 300, data: 'ns1.entreprise.com.' }]);
      return dnsAnswers([{ name: 'entreprise.com.', type: 1, TTL: 60, data: '203.0.113.10' }]);
    }]
  ]);

  const result = await checks.checkDns('entreprise.com', { timeout: 1000 });
  assert.equal(result.error, null);
  assert.equal(result.hasMx, true);
  assert.equal(result.mxCount, 1);
  assert.equal(result.hasSpf, true);
  assert.equal(result.spfAll, '~all');
  assert.equal(result.hasDmarc, true);
  assert.equal(result.dmarcPolicy, 'reject');
  assert.equal(result.hasA, true);
  assert.deepEqual(result.ips, ['203.0.113.10']);
  assert.equal(result.hasNs, true);
  assert.equal(result.resolvable, true);
});

test('checkDns détecte le « null MX » (0 .) : domaine sans réception d’email', async () => {
  mockFetch([
    ['dns.google', (url) => {
      if (url.includes('type=MX')) return dnsAnswers([{ name: 'entreprise.com.', type: 15, TTL: 3600, data: '0 .' }]);
      if (url.includes('_dmarc.')) return dnsAnswers([{ name: '_dmarc.entreprise.com.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }]);
      if (url.includes('type=TXT')) return dnsAnswers([{ name: 'entreprise.com.', type: 16, TTL: 300, data: '"v=spf1 -all"' }]);
      if (url.includes('type=NS')) return dnsAnswers([{ name: 'entreprise.com.', type: 2, TTL: 300, data: 'ns1.example.net.' }]);
      return dnsAnswers([{ name: 'entreprise.com.', type: 1, TTL: 60, data: '76.223.54.146' }]);
    }]
  ]);

  const result = await checks.checkDns('entreprise.com', { timeout: 1000 });
  assert.equal(result.hasMx, false);
  assert.equal(result.nullMx, true);
  assert.equal(result.mxCount, 0);
  assert.equal(result.spf, 'v=spf1 -all');
  assert.equal(result.spfAll, '-all');
});

test('checkDns distingue « aucun MX » d’« échec de la requête MX »', async () => {
  // Seule la requête MX échoue : les autres répondent normalement.
  globalThis.fetch = async (url) => {
    const target = String(url);
    if (target.includes('type=MX')) {
      const err = new Error('aborted');
      err.name = 'AbortError';
      throw err;
    }
    if (target.includes('_dmarc.')) return jsonResponse({ Status: 0, Answer: [{ name: '_dmarc.x.com.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }] });
    if (target.includes('type=TXT')) return jsonResponse({ Status: 0, Answer: [{ name: 'x.com.', type: 16, TTL: 300, data: '"v=spf1 -all"' }] });
    if (target.includes('type=NS')) return jsonResponse({ Status: 0, Answer: [{ name: 'x.com.', type: 2, TTL: 300, data: 'ns1.x.com.' }] });
    return jsonResponse({ Status: 0, Answer: [{ name: 'x.com.', type: 1, TTL: 60, data: '203.0.113.9' }] });
  };

  const result = await checks.checkDns('x.com', { timeout: 5 });
  assert.equal(result.error, null, 'une seule requête en échec ne doit pas invalider tout le DNS');
  assert.equal(result.mxKnown, false, 'l’échec de la requête MX doit être signalé');
  assert.equal(result.hasMx, false);
  assert.match(result.partialError, /MX:timeout/);
  assert.equal(result.txtKnown, true);
  assert.equal(result.dmarcKnown, true);

  const scored = require('../lib/scoring').computeScore({ dns: result, rdap: { found: true, ageDays: 4000 }, disposable: { listed: false }, urlscan: {} });
  assert.equal(scored.score, 0, 'aucun point ne doit être imputé sur une donnée indisponible');
});

test('checkDns marque un domaine inexistant (NXDOMAIN) comme non résolvable', async () => {
  mockFetch([['dns.google', () => nxdomain()]]);
  const result = await checks.checkDns('domaine-qui-nexiste-pas-12345.tld', { timeout: 1000 });
  assert.equal(result.resolvable, false);
  assert.equal(result.hasA, false);
  assert.equal(result.hasMx, false);
});

test('checkDns signale une panne DNS totale au lieu de mentir sur les critères', async () => {
  globalThis.fetch = async () => {
    const err = new Error('aborted');
    err.name = 'AbortError';
    throw err;
  };
  const result = await checks.checkDns('entreprise.com', { timeout: 5 });
  assert.equal(result.error, 'all_queries_failed');
  assert.equal(result.resolvable, null);
});

/* ----------------------------- RDAP ------------------------------------- */

test('checkRdap calcule l’âge du domaine et lit le registrar', async () => {
  mockFetch([
    ['rdap.org', () =>
      jsonResponse({
        ldhName: 'ENTREPRISE.COM',
        status: ['client transfer prohibited'],
        events: [
          { eventAction: 'registration', eventDate: '2010-05-04T00:00:00Z' },
          { eventAction: 'expiration', eventDate: '2030-05-04T00:00:00Z' }
        ],
        entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]] }]
      })
    ]
  ]);

  const result = await checks.checkRdap('entreprise.com', { timeout: 1000 });
  assert.equal(result.found, true);
  assert.equal(result.createdAt, '2010-05-04T00:00:00Z');
  assert.equal(result.registrar, 'Example Registrar');
  assert.ok(result.ageDays > 5000, `ageDays=${result.ageDays}`);
  assert.deepEqual(result.statuses, ['client transfer prohibited']);
});

test('checkRdap gère un domaine absent (404) et une panne (timeout)', async () => {
  mockFetch([['rdap.org', () => jsonResponse({ errorCode: 404 }, 404)]]);
  assert.equal((await checks.checkRdap('inexistant.tld', { timeout: 1000 })).found, false);

  globalThis.fetch = async () => {
    const err = new Error('aborted');
    err.name = 'AbortError';
    throw err;
  };
  const down = await checks.checkRdap('entreprise.com', { timeout: 5 });
  assert.equal(down.found, null);
  assert.match(String(down.error), /timeout|registry|fetch inattendu/);
});

test('parseSpf n’emprunte pas les autres TXT du domaine (cas google.com)', () => {
  // Google renvoie la chaîne SPF suivie de plusieurs TXT de vérification dans le même bloc.
  const concatenated =
    'v=spf1 include:_spf.google.com ~all google-site-verification=4ibFUgB-wXLQ_S7vsXVomSTVamuOXBiVAzpR5IZ87D0 onetrust-domain-verification=0d477fe608074e6f9c12bca7826035cc';
  assert.equal(checks.parseSpf(concatenated), 'v=spf1 include:_spf.google.com ~all');
});

test('parseSpf gère les guillemets, les mécanismes et l’absence de SPF', () => {
  assert.equal(checks.parseSpf('"v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all"'), 'v=spf1 ip4:203.0.113.0/24 ip6:2001:db8::/32 -all');
  assert.equal(checks.parseSpf('v=spf1 mx a:mail.entreprise.com redirect=_spf.entreprise.com'), 'v=spf1 mx a:mail.entreprise.com redirect=_spf.entreprise.com');
  assert.equal(checks.parseSpf('"google-site-verification=abc"'), null);
  assert.equal(checks.parseSpf(''), null);
  assert.equal(checks.parseSpf(null), null);
});

test('parseDmarcPolicy lit p=none / quarantine / reject et ignore le reste', () => {
  assert.equal(checks.parseDmarcPolicy('v=DMARC1; p=reject; rua=mailto:d@x.com'), 'reject');
  assert.equal(checks.parseDmarcPolicy('v=DMARC1;p=quarantine;fo=1'), 'quarantine');
  assert.equal(checks.parseDmarcPolicy('v=DMARC1; p=none'), 'none');
  assert.equal(checks.parseDmarcPolicy('v=DMARC1; rua=mailto:d@x.com'), null);
  assert.equal(checks.parseDmarcPolicy('autre chose'), null);
});

test('toutes les requêtes sortantes portent un User-Agent explicite (rdap.org renvoie 403 sinon)', async () => {
  const calls = mockFetch([['rdap.org', () => jsonResponse({ ldhName: 'X.COM', events: [] })]]);
  await checks.checkRdap('x.com', { timeout: 1000 });
  assert.equal(calls[0].options.headers['user-agent'], checks.USER_AGENT);
  assert.ok(checks.USER_AGENT.length > 5);
});

test('checkRdap bascule sur le registre officiel si rdap.org est bloqué (403)', async () => {
  const calls = mockFetch([
    ['rdap.org', () => jsonResponse({}, 403)],
    ['data.iana.org', () =>
      jsonResponse({ services: [[['com', 'net'], ['https://rdap.verisign.com/com/v1/']]] })
    ],
    ['rdap.verisign.com', () =>
      jsonResponse({ ldhName: 'GOOGLE.COM', events: [{ eventAction: 'registration', eventDate: '1997-09-15T04:00:00Z' }] })
    ]
  ]);

  const result = await checks.checkRdap('google.com', { timeout: 1000 });
  assert.equal(result.found, true);
  assert.equal(result.via, 'registry');
  assert.equal(result.createdAt, '1997-09-15T04:00:00Z');
  assert.ok(calls.some((c) => c.url.includes('rdap.verisign.com')));
});

test('checkRdap renseigne la voie utilisée quand rdap.org répond', async () => {
  mockFetch([['rdap.org', () => jsonResponse({ ldhName: 'X.COM', events: [{ eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' }] })]]);
  const result = await checks.checkRdap('x.com', { timeout: 1000 });
  assert.equal(result.via, 'rdap.org');
});

/* ----------------------------- domaines jetables ------------------------ */

test('checkDisposable reconnaît un domaine jetable et son sous-domaine (liste locale de secours)', async () => {
  const direct = await checks.checkDisposable('yopmail.com', { offline: true });
  assert.equal(direct.listed, true);
  assert.equal(direct.matchedOn, 'yopmail.com');
  assert.equal(direct.source, 'seed');

  const sub = await checks.checkDisposable('boite.yopmail.com', { offline: true });
  assert.equal(sub.listed, true);
  assert.equal(sub.matchedOn, 'yopmail.com', 'le sous-domaine doit être rattaché à son domaine enregistré');
});

test('checkDisposable ne signale pas un domaine légitime', async () => {
  const result = await checks.checkDisposable('entreprise.com', { offline: true });
  assert.equal(result.listed, false);
  assert.equal(result.matchedOn, null);
});

test('checkDisposable retombe sur la liste locale si la liste publique est injoignable', async () => {
  mockFetch([['raw.githubusercontent.com', () => jsonResponse({}, 500)]]);
  const result = await checks.checkDisposable('yopmail.com', { forceRefresh: true, timeout: 500 });
  assert.equal(result.source, 'seed');
  assert.equal(result.listed, true);
  assert.ok(result.listSize > 40);
});

/* ----------------------------- urlscan ---------------------------------- */

test('checkUrlscan compte les analyses au verdict malveillant', async () => {
  mockFetch([
    ['urlscan.io', () =>
      jsonResponse({
        total: 12,
        results: [
          { task: { time: '2026-01-01T10:00:00Z' }, verdicts: { overall: { malicious: true } }, stats: { uniqIPs: 4 } },
          { task: { time: '2026-03-02T10:00:00Z' }, verdicts: { overall: { malicious: false } } },
          { task: { time: '2025-12-01T10:00:00Z' } }
        ]
      })
    ]
  ]);

  const result = await checks.checkUrlscan('entreprise.com', { timeout: 1000 });
  assert.equal(result.total, 12);
  assert.equal(result.maliciousScans, 1);
  assert.equal(result.lastScan, '2026-03-02T10:00:00Z');
  assert.equal(result.uniqIPs, 4);
});

test('checkUrlscan gère la limite d’appels (429) sans casser l’analyse', async () => {
  mockFetch([['urlscan.io', () => jsonResponse({ message: 'too many requests' }, 429)]]);
  const result = await checks.checkUrlscan('entreprise.com', { timeout: 1000 });
  assert.equal(result.error, 'rate_limited');
});

/* ----------------------------- VirusTotal (optionnel) ------------------- */

test('checkVirusTotal est désactivé sans clé — comportement normal attendu', async () => {
  const result = await checks.checkVirusTotal('entreprise.com', '');
  assert.deepEqual(result, { enabled: false });
});

test('checkVirusTotal lit les statistiques quand une clé est fournie', async () => {
  const calls = mockFetch([
    ['virustotal.com', () =>
      jsonResponse({
        data: {
          attributes: {
            last_analysis_stats: { malicious: 2, suspicious: 1, harmless: 70, undetected: 5 },
            reputation: 15,
            categories: { Forcepoint: 'business' },
            last_analysis_date: 1767225600
          }
        }
      })
    ]
  ]);

  const result = await checks.checkVirusTotal('entreprise.com', 'CLE_FACTICE_POUR_TEST', { timeout: 1000 });
  assert.equal(result.enabled, true);
  assert.equal(result.malicious, 2);
  assert.equal(result.suspicious, 1);
  assert.deepEqual(result.categories, ['business']);
  assert.equal(calls[0].options.headers['x-apikey'], 'CLE_FACTICE_POUR_TEST');
});

test('checkVirusTotal distingue clé invalide et quota dépassé', async () => {
  mockFetch([['virustotal.com', () => jsonResponse({ error: { code: 'WrongCredentialsError' } }, 401)]]);
  assert.equal((await checks.checkVirusTotal('a.com', 'k', { timeout: 500 })).error, 'invalid_key');

  mockFetch([['virustotal.com', () => jsonResponse({ error: { code: 'QuotaExceededError' } }, 429)]]);
  assert.equal((await checks.checkVirusTotal('a.com', 'k', { timeout: 500 })).error, 'quota_exceeded');
});

/* ----------------------------- orchestration ---------------------------- */

test('collectSignals renvoie toutes les sources et leur état, sans exception', async () => {
  mockFetch([
    ['dns.google', (url) => {
      if (url.includes('type=MX')) return dnsAnswers([{ name: 'entreprise.com.', type: 15, TTL: 300, data: '10 mx1.entreprise.com.' }]);
      if (url.includes('_dmarc.')) return dnsAnswers([{ name: '_dmarc.entreprise.com.', type: 16, TTL: 300, data: '"v=DMARC1; p=reject"' }]);
      if (url.includes('type=TXT')) return dnsAnswers([{ name: 'entreprise.com.', type: 16, TTL: 300, data: '"v=spf1 -all"' }]);
      if (url.includes('type=NS')) return dnsAnswers([{ name: 'entreprise.com.', type: 2, TTL: 300, data: 'ns1.example.net.' }]);
      return dnsAnswers([{ name: 'entreprise.com.', type: 1, TTL: 60, data: '76.223.54.146' }]);
    }],
    ['rdap.org', () => jsonResponse({ ldhName: 'ENTREPRISE.COM', events: [{ eventAction: 'registration', eventDate: '2010-01-01T00:00:00Z' }] })],
    ['urlscan.io', () => jsonResponse({ total: 0, results: [] })],
    ['raw.githubusercontent.com', () => jsonResponse({}, 500)]
  ]);

  const collected = await checks.collectSignals('mail.entreprise.com', { offline: true, timeout: 1000 });
  assert.equal(collected.domain, 'mail.entreprise.com');
  assert.equal(collected.registeredDomain, 'entreprise.com');
  assert.deepEqual(Object.keys(collected.sources).sort(), ['blocklist', 'dns', 'rdap', 'urlscan', 'virustotal']);
  assert.equal(collected.sources.dns, 'ok');
  assert.equal(collected.sources.rdap, 'ok');
  assert.equal(collected.sources.virustotal, 'disabled');
  assert.equal(collected.signals.disposable.listed, false);
  assert.ok(collected.durationMs >= 0);
});

test('domainExists distingue domaine inexistant, existant et indéterminé', () => {
  assert.equal(checks.domainExists({ dns: { resolvable: false, hasA: false, hasNs: false, hasMx: false }, rdap: { found: false } }), false);
  assert.equal(checks.domainExists({ dns: { resolvable: true, hasA: true, hasNs: true, hasMx: true }, rdap: { found: true } }), true);
  assert.equal(checks.domainExists({ dns: { error: 'all_queries_failed', resolvable: null }, rdap: { found: null } }), null);
});
