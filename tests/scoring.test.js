'use strict';
/**
 * Email Domain Security — tests du barème de risque (module pur, aucun réseau).
 * Lancement : node --test tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { computeScore, WEIGHTS, THRESHOLDS } = require('../lib/scoring');

/** Signaux d'un domaine parfaitement propre. */
function cleanSignals(overrides = {}) {
  const base = {
    dns: {
      error: null,
      resolvable: true,
      hasMx: true,
      nullMx: false,
      mxCount: 1,
      hasSpf: true,
      spf: 'v=spf1 include:_spf.example.com -all',
      spfAll: '-all',
      hasDmarc: true,
      dmarcPolicy: 'reject',
      hasA: true,
      hasNs: true
    },
    rdap: { found: true, ageDays: 4000, createdAt: '2013-01-01T00:00:00Z' },
    disposable: { listed: false, matchedOn: null, source: 'blocklist', listSize: 8857, error: null },
    urlscan: { total: 0, sampled: 0, maliciousScans: 0 },
    virustotal: { enabled: false }
  };
  return {
    ...base,
    ...overrides,
    dns: { ...base.dns, ...(overrides.dns || {}) },
    rdap: { ...base.rdap, ...(overrides.rdap || {}) },
    disposable: { ...base.disposable, ...(overrides.disposable || {}) },
    urlscan: { ...base.urlscan, ...(overrides.urlscan || {}) },
    virustotal: { ...base.virustotal, ...(overrides.virustotal || {}) }
  };
}

test('domaine propre -> score 0, LOW, GOOD', () => {
  const result = computeScore(cleanSignals());
  assert.equal(result.score, 0);
  assert.equal(result.risk, 'LOW');
  assert.equal(result.reputation, 'GOOD');
  assert.equal(result.reasons.length, 0);
});

test('domaine jetable -> HIGH + MALICIOUS (critère rédhibitoire)', () => {
  const result = computeScore(cleanSignals({ disposable: { listed: true, matchedOn: 'yopmail.com' } }));
  assert.equal(result.score, WEIGHTS.DISPOSABLE_LISTED);
  assert.equal(result.risk, 'HIGH');
  assert.equal(result.reputation, 'MALICIOUS');
  assert.equal(result.hardFail, true);
  assert.equal(result.reasons[0].code, 'DISPOSABLE_LISTED');
});

test('absence de MX -> +25 -> MEDIUM', () => {
  const result = computeScore(cleanSignals({ dns: { hasMx: false, nullMx: false } }));
  assert.equal(result.score, WEIGHTS.NO_MX);
  assert.equal(result.risk, 'MEDIUM');
  assert.equal(result.reputation, 'SUSPICIOUS');
  assert.equal(result.reasons[0].code, 'NO_MX');
});

test('null MX (0 .) -> même traitement que l’absence de MX, avec un message distinct', () => {
  const result = computeScore(cleanSignals({ dns: { hasMx: false, nullMx: true } }));
  assert.equal(result.score, WEIGHTS.NO_MX);
  assert.match(result.reasons[0].label, /null MX/);
});

test('SPF absent + DMARC absent -> +20 -> LOW (limite haute)', () => {
  const result = computeScore(cleanSignals({ dns: { hasSpf: false, spf: null, spfAll: null, hasDmarc: false, dmarcPolicy: null } }));
  assert.equal(result.score, WEIGHTS.SPF_MISSING + WEIGHTS.DMARC_MISSING);
  assert.equal(result.risk, 'LOW');
});

test('bornes du barème : 24 = LOW, 25 = MEDIUM, 59 = MEDIUM, 60 = HIGH', () => {
  // 24 = SPF 10 + DMARC 10 + quarantine 2 + urlscan 2 ?  -> on fabrique exactement 24 avec URLSCAN(10)+SPF(10)+DMARC(5)... test direct ci-dessous
  const cases = [
    { score: 24, expected: 'LOW' },
    { score: 25, expected: 'MEDIUM' },
    { score: 59, expected: 'MEDIUM' },
    { score: 60, expected: 'HIGH' }
  ];
  for (const c of cases) {
    const risk = c.score <= THRESHOLDS.LOW_MAX ? 'LOW' : c.score <= THRESHOLDS.MEDIUM_MAX ? 'MEDIUM' : 'HIGH';
    assert.equal(risk, c.expected, `score ${c.score}`);
  }
});

test('domaine récent (< 30 j) cumulé à MX/SPF/DMARC manquants -> HIGH', () => {
  const result = computeScore(
    cleanSignals({
      dns: { hasMx: false, hasSpf: false, spf: null, spfAll: null, hasDmarc: false, dmarcPolicy: null },
      rdap: { found: true, ageDays: 12 }
    })
  );
  assert.equal(result.score, 30 + 25 + 10 + 10);
  assert.equal(result.risk, 'HIGH');
});

test('paliers d’âge : 29 j / 89 j / 364 j', () => {
  assert.equal(computeScore(cleanSignals({ rdap: { ageDays: 29 } })).score, WEIGHTS.DOMAIN_AGE_30);
  assert.equal(computeScore(cleanSignals({ rdap: { ageDays: 89 } })).score, WEIGHTS.DOMAIN_AGE_90);
  assert.equal(computeScore(cleanSignals({ rdap: { ageDays: 364 } })).score, WEIGHTS.DOMAIN_AGE_365);
  assert.equal(computeScore(cleanSignals({ rdap: { ageDays: 365 } })).score, 0);
});

test('SPF +all -> +15, SPF ~all -> +5, SPF -all -> 0', () => {
  assert.equal(computeScore(cleanSignals({ dns: { spfAll: '+all' } })).score, WEIGHTS.SPF_PASS_ALL);
  assert.equal(computeScore(cleanSignals({ dns: { spfAll: '~all' } })).score, WEIGHTS.SPF_SOFTFAIL);
  assert.equal(computeScore(cleanSignals({ dns: { spfAll: '-all' } })).score, 0);
});

test('DMARC p=none -> +5, p=quarantine -> +2, p=reject -> 0', () => {
  assert.equal(computeScore(cleanSignals({ dns: { dmarcPolicy: 'none' } })).score, WEIGHTS.DMARC_NONE);
  assert.equal(computeScore(cleanSignals({ dns: { dmarcPolicy: 'quarantine' } })).score, WEIGHTS.DMARC_QUARANTINE);
  assert.equal(computeScore(cleanSignals({ dns: { dmarcPolicy: 'reject' } })).score, 0);
});

test('VirusTotal : >= 3 moteurs -> rédhibitoire (HIGH + MALICIOUS)', () => {
  const result = computeScore(cleanSignals({ virustotal: { enabled: true, malicious: 5, suspicious: 0 } }));
  assert.equal(result.score, WEIGHTS.VT_MALICIOUS_3);
  assert.equal(result.risk, 'HIGH');
  assert.equal(result.reputation, 'MALICIOUS');
});

test('VirusTotal : 1-2 moteurs -> +15 seulement, pas rédhibitoire', () => {
  const result = computeScore(cleanSignals({ virustotal: { enabled: true, malicious: 2, suspicious: 0 } }));
  assert.equal(result.score, WEIGHTS.VT_MALICIOUS_ANY);
  assert.equal(result.risk, 'LOW');
  assert.equal(result.reputation, 'GOOD');
});

test('VirusTotal : 2 moteurs suspicieux -> +20', () => {
  const result = computeScore(cleanSignals({ virustotal: { enabled: true, malicious: 0, suspicious: 3 } }));
  assert.equal(result.score, WEIGHTS.VT_SUSPICIOUS_2);
  assert.equal(result.risk, 'LOW');
});

test('urlscan malveillant -> +10, jamais décisif seul', () => {
  const result = computeScore(cleanSignals({ urlscan: { total: 3, maliciousScans: 1 } }));
  assert.equal(result.score, WEIGHTS.URLSCAN_MALICIOUS);
  assert.equal(result.risk, 'LOW');
});

test('DNS totalement indisponible -> avertissement, aucun point DNS imputé', () => {
  const result = computeScore(cleanSignals({ dns: { error: 'all_queries_failed', hasMx: null, hasSpf: null, hasDmarc: null } }));
  assert.equal(result.score, 0);
  assert.equal(result.warnings.length, 1);
  assert.equal(result.warnings[0].code, 'DNS_UNAVAILABLE');
  assert.equal(result.reasons.length, 0);
});

test('aucune source exploitable -> réputation UNKNOWN', () => {
  const result = computeScore({
    dns: { error: 'all_queries_failed' },
    rdap: { found: null, error: 'timeout' },
    disposable: { listed: null, error: 'timeout' },
    urlscan: { error: 'timeout' },
    virustotal: { enabled: false }
  });
  assert.equal(result.reputation, 'UNKNOWN');
});

test('le score est plafonné à 100 même si la somme dépasse', () => {
  const result = computeScore(
    cleanSignals({
      dns: { hasMx: false, hasSpf: false, spf: null, spfAll: null, hasDmarc: false, dmarcPolicy: null },
      rdap: { ageDays: 3 },
      disposable: { listed: true, matchedOn: 'tempmail.org' }
    })
  );
  assert.equal(result.rawScore, 60 + 25 + 30 + 10 + 10);
  assert.equal(result.score, 100);
  assert.equal(result.risk, 'HIGH');
});

test('une requête MX en échec ne doit PAS être lue comme « aucun MX »', () => {
  // Cas réel observé : une panne réseau ponctuelle sur la requête MX faisait
  // passer google.com en MEDIUM (25 + 5) alors qu'il publie bien un MX.
  const result = computeScore(cleanSignals({ dns: { hasMx: false, mxKnown: false } }));
  assert.equal(result.score, 0);
  assert.equal(result.risk, 'LOW');
  assert.equal(result.reasons.some((r) => r.code === 'NO_MX'), false);
  assert.equal(result.warnings.some((w) => w.code === 'DNS_MX_UNAVAILABLE'), true);
});

test('une requête SPF ou DMARC en échec neutralise le critère correspondant', () => {
  const spfDown = computeScore(cleanSignals({ dns: { hasSpf: false, spf: null, spfAll: null, txtKnown: false } }));
  assert.equal(spfDown.score, 0);
  assert.equal(spfDown.warnings.some((w) => w.code === 'DNS_SPF_UNAVAILABLE'), true);

  const dmarcDown = computeScore(cleanSignals({ dns: { hasDmarc: false, dmarcPolicy: null, dmarcKnown: false } }));
  assert.equal(dmarcDown.score, 0);
  assert.equal(dmarcDown.warnings.some((w) => w.code === 'DNS_DMARC_UNAVAILABLE'), true);
});

test('les seuils et pondérations restent inchangés (contrôle de non-régression)', () => {
  assert.equal(WEIGHTS.DISPOSABLE_LISTED, 60);
  assert.equal(WEIGHTS.NO_MX, 25);
  assert.equal(WEIGHTS.DOMAIN_AGE_30, 30);
  assert.equal(WEIGHTS.DOMAIN_AGE_90, 20);
  assert.equal(WEIGHTS.DOMAIN_AGE_365, 10);
  assert.equal(WEIGHTS.SPF_MISSING, 10);
  assert.equal(WEIGHTS.SPF_SOFTFAIL, 5);
  assert.equal(WEIGHTS.SPF_PASS_ALL, 15);
  assert.equal(WEIGHTS.DMARC_MISSING, 10);
  assert.equal(WEIGHTS.DMARC_NONE, 5);
  assert.equal(WEIGHTS.DMARC_QUARANTINE, 2);
  assert.equal(WEIGHTS.VT_MALICIOUS_3, 45);
  assert.equal(WEIGHTS.VT_MALICIOUS_ANY, 15);
  assert.equal(WEIGHTS.VT_SUSPICIOUS_2, 20);
  assert.equal(WEIGHTS.URLSCAN_MALICIOUS, 10);
  assert.equal(THRESHOLDS.LOW_MAX, 24);
  assert.equal(THRESHOLDS.MEDIUM_MAX, 59);
});

test('les critères sont triés du plus lourd au plus léger', () => {
  const result = computeScore(
    cleanSignals({
      dns: { hasMx: false, hasSpf: false, spf: null, spfAll: null, hasDmarc: false, dmarcPolicy: null },
      rdap: { ageDays: 10 }
    })
  );
  const points = result.reasons.map((r) => r.points);
  assert.deepEqual(points, [...points].sort((a, b) => b - a));
});
