'use strict';
/**
 * Email Domain Security — Collecte des signaux de sécurité d'un domaine.
 *
 * SOCLE SANS CLÉ (aucune inscription, aucun secret) :
 *   1. DNS-over-HTTPS  (dns.google)  -> MX, SPF (TXT), DMARC (_dmarc), A, NS
 *   2. RDAP            (rdap.org)    -> date de création, expiration, registrar, statuts
 *   3. Liste publique de domaines jetables (disposable-email-domains)
 *   4. urlscan.io                    -> analyses publiques existantes sur le domaine
 *
 * ENRICHISSEMENT OPTIONNEL : VirusTotal (uniquement si une clé est fournie).
 *
 * Aucune clé n'est écrite ici : la clé VirusTotal est toujours passée en
 * paramètre (elle vient de process.env côté serveur).
 *
 * Toutes les fonctions renvoient un objet ; aucune ne lève d'exception :
 * une source en panne doit dégrader le rapport, pas casser l'application.
 */

const fs = require('node:fs');
const path = require('node:path');

const DOH_URL = 'https://dns.google/resolve';
const RDAP_URL = 'https://rdap.org/domain/';
const DISPOSABLE_LIST_URL =
  'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf';
const URLSCAN_SEARCH_URL = 'https://urlscan.io/api/v1/search/';
const VT_DOMAIN_URL = 'https://www.virustotal.com/api/v3/domains/';
const SEED_LIST_FILE = path.join(__dirname, '..', 'data', 'disposable-seed.txt');

const DEFAULT_TIMEOUT = 7000;
const LIST_TTL_MS = 12 * 60 * 60 * 1000; // 12 h
const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000; // 24 h

// User-Agent explicite OBLIGATOIRE : rdap.org est derrière Cloudflare et
// renvoie 403 au User-Agent par défaut de Node (undici). Constaté en test réel.
const USER_AGENT = 'email-domain-security/1.0 (+analyse de domaine email)';

// Table officielle IANA : quel registre RDAP interroger selon l'extension.
const IANA_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

// Extensions à deux niveaux courantes : permet d'extraire correctement le
// « domaine enregistré » (ex. mon-entreprise.co.uk -> mon-entreprise.co.uk).
const MULTI_LEVEL_TLDS = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.fr', 'co.fr', 'asso.fr', 'org.fr', 'net.fr', 'gouv.fr',
  'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.kr', 'co.in',
  'com.br', 'com.mx', 'com.ar', 'co.za', 'com.tr', 'com.cn', 'com.pt'
]);

/* ------------------------------------------------------------------ *
 * 1. Validation d'email et extraction du domaine
 * ------------------------------------------------------------------ */

const EMAIL_RE =
  /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

/** Validation syntaxique volontairement stricte (pas de requête réseau). */
function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  const value = email.trim();
  if (value.length < 6 || value.length > 254) return false;
  if (value.includes('..')) return false;
  if (!EMAIL_RE.test(value)) return false;
  const domain = value.slice(value.lastIndexOf('@') + 1);
  if (domain.length > 253) return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) return false; // adresse IP littérale : hors périmètre
  const tld = domain.slice(domain.lastIndexOf('.') + 1);
  if (tld.length < 2 || /^\d+$/.test(tld)) return false;
  return true;
}

/** contact@entreprise.com -> entreprise.com */
function extractDomain(email) {
  if (typeof email !== 'string' || !email.includes('@')) return null;
  const raw = email.trim().slice(email.trim().lastIndexOf('@') + 1).toLowerCase();
  const domain = raw.replace(/\.+$/, '');
  return domain || null;
}

/** Réduit un hôte à son domaine enregistré (sans www., sans sous-domaine). */
function registeredDomain(host) {
  if (typeof host !== 'string') return null;
  const clean = host.toLowerCase().replace(/\.+$/, '');
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_LEVEL_TLDS.has(lastTwo)) return parts.slice(-3).join('.');
  return lastTwo;
}

/* ------------------------------------------------------------------ *
 * 2. Utilitaires réseau (timeout systématique, erreurs capturées)
 * ------------------------------------------------------------------ */

async function fetchText(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout || DEFAULT_TIMEOUT);
  try {
    const res = await fetch(url, {
      headers: { 'user-agent': USER_AGENT, ...(options.headers || {}) },
      redirect: 'follow',
      signal: controller.signal
    });
    const text = await res.text();
    return { ok: res.ok, status: res.status, text };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      text: '',
      error: err && err.name === 'AbortError' ? 'timeout' : (err && err.message) || 'network_error'
    };
  } finally {
    clearTimeout(timer);
  }
}

async function fetchJson(url, options = {}) {
  const res = await fetchText(url, options);
  let json = null;
  if (res.text) {
    try {
      json = JSON.parse(res.text);
    } catch {
      json = null;
    }
  }
  return { ...res, json };
}

function firstMatch(value, regex) {
  if (typeof value !== 'string') return null;
  const match = value.match(regex);
  return match ? match[0] : null;
}

// Jetons légitimes d'une entrée SPF. Sert à s'arrêter proprement quand le
// fournisseur DNS renvoie plusieurs TXT concaténés (ex. google.com, où la chaîne
// SPF est suivie de plusieurs « google-site-verification=... »).
const SPF_TOKEN_RE =
  /^(v=spf1|[~+\-?]?all|include:[^\s]+|ip4:[^\s]+|ip6:[^\s]+|a(?::[^\s]+)?|mx(?::[^\s]+)?|ptr(?::[^\s]+)?|exists:[^\s]+|redirect=[^\s]+|exp=[^\s]+)$/i;

/** Extrait l'entrée SPF d'un bloc TXT, sans déborder sur les autres TXT. */
function parseSpf(txtData) {
  if (typeof txtData !== 'string' || !txtData) return null;
  const tokens = txtData.replace(/["\\]/g, ' ').trim().split(/\s+/).filter(Boolean);
  const start = tokens.findIndex((token) => /^v=spf1$/i.test(token));
  if (start === -1) return null;

  const kept = [];
  for (let index = start; index < tokens.length; index += 1) {
    if (!SPF_TOKEN_RE.test(tokens[index])) break;
    kept.push(tokens[index]);
  }
  return kept.join(' ');
}

/** Politique DMARC : 'none' | 'quarantine' | 'reject' | null. */
function parseDmarcPolicy(txtData) {
  if (typeof txtData !== 'string' || !/v=DMARC1/i.test(txtData)) return null;
  const match = /(?:^|[;\s])p\s*=\s*(none|quarantine|reject)\b/i.exec(txtData);
  return match ? match[1].toLowerCase() : null;
}

/* ------------------------------------------------------------------ *
 * 3. Source 1 — DNS-over-HTTPS
 * ------------------------------------------------------------------ */

/** Interroge dns.google. Status: 0 = NOERROR, 3 = NXDOMAIN. */
async function dohQuery(name, type, options = {}) {
  const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
  const res = await fetchJson(url, {
    headers: { accept: 'application/dns-json' },
    timeout: options.timeout
  });
  if (!res.ok && res.status !== 404) {
    return { type, status: null, records: [], error: res.error || `http_${res.status}` };
  }
  const answers = (res.json && res.json.Answer) || [];
  return {
    type,
    status: res.json ? res.json.Status : null,
    records: answers.map((a) => ({ name: a.name, type: a.type, ttl: a.TTL, data: String(a.data || '') }))
  };
}

/** MX / SPF / DMARC / A / NS en une passe parallèle. */
async function checkDns(domain, options = {}) {
  const [mx, txt, dmarc, a, ns] = await Promise.all([
    dohQuery(domain, 'MX', options),
    dohQuery(domain, 'TXT', options),
    dohQuery(`_dmarc.${domain}`, 'TXT', options),
    dohQuery(domain, 'A', options),
    dohQuery(domain, 'NS', options)
  ]);

  const errors = [mx, txt, dmarc, a, ns]
    .filter((record) => record.error)
    .map((record) => `${record.type}:${record.error}`);

  const txtData = txt.records.map((r) => r.data).join(' ');
  const spf = parseSpf(txtData);

  const dmarcData = dmarc.records.map((r) => r.data).join(' ');
  const dmarcPolicy = parseDmarcPolicy(dmarcData);
  const hasDmarc = dmarcPolicy !== null || /v=DMARC1/i.test(dmarcData);

  const mxRecords = mx.records.map((r) => r.data.trim());
  const nullMx = mxRecords.some((d) => /^0\s+\.$/.test(d));
  const usableMx = mxRecords.filter((d) => !/^0\s+\.$/.test(d));

  const allFailed = errors.length === 5;
  const nxdomain = a.status === 3 && ns.status === 3;

  return {
    error: allFailed ? 'all_queries_failed' : null,
    partialError: !allFailed && errors.length > 0 ? errors.join(', ') : null,
    resolvable: allFailed ? null : !nxdomain,
    // Une requête qui a ÉCHOUÉ n'est pas une requête qui a répondu « rien » :
    // ces drapeaux évitent de pénaliser un domaine sur une simple panne réseau.
    mxKnown: !mx.error,
    txtKnown: !txt.error,
    dmarcKnown: !dmarc.error,
    hasA: a.records.length > 0,
    ips: a.records.map((r) => r.data).slice(0, 4),
    hasNs: ns.records.length > 0,
    hasMx: usableMx.length > 0,
    nullMx,
    mxCount: usableMx.length,
    mxRecords: usableMx.slice(0, 3),
    hasSpf: Boolean(spf),
    spf,
    spfAll: spf ? (firstMatch(spf, /([~+\-?]all)/i) || '').toLowerCase() : null,
    hasDmarc,
    dmarcPolicy,
    txtRecordCount: txt.records.length
  };
}

/* ------------------------------------------------------------------ *
 * 4. Source 2 — RDAP (données d'enregistrement du domaine)
 *    Deux voies : rdap.org (simple), puis repli sur le registre officiel
 *    indiqué par la table de bootstrap IANA si la première échoue.
 * ------------------------------------------------------------------ */

let bootstrapCache = { at: 0, map: null };

/** Table IANA tld -> URL du registre RDAP (mise en cache 24 h). */
async function loadBootstrap(options = {}) {
  if (bootstrapCache.map && Date.now() - bootstrapCache.at < BOOTSTRAP_TTL_MS) return bootstrapCache.map;

  const res = await fetchJson(IANA_BOOTSTRAP_URL, {
    headers: { accept: 'application/json' },
    timeout: options.timeout || 10000
  });
  if (!res.ok || !res.json || !Array.isArray(res.json.services)) return bootstrapCache.map;

  const map = new Map();
  for (const service of res.json.services) {
    const [tlds, urls] = service;
    if (!Array.isArray(urls) || !urls.length) continue;
    // Format officiel : tlds est un tableau (["com","net"]) ; on tolère aussi une chaîne.
    const list = Array.isArray(tlds) ? tlds : [tlds];
    for (const tld of list) {
      if (tld) map.set(String(tld).toLowerCase(), String(urls[0]).replace(/\/+$/, ''));
    }
  }
  bootstrapCache = { at: Date.now(), map };
  return map;
}

/** Transforme une réponse RDAP en signaux exploitables. */
function parseRdap(data, via) {
  const events = Array.isArray(data.events) ? data.events : [];
  const eventDate = (action) => {
    const found = events.find((e) => String(e.eventAction || '').toLowerCase() === action);
    return found ? found.eventDate : null;
  };

  const createdAt = eventDate('registration') || null;
  const expiresAt = eventDate('expiration') || null;

  let ageDays = null;
  if (createdAt) {
    const ts = Date.parse(createdAt);
    if (!Number.isNaN(ts)) ageDays = Math.max(0, Math.floor((Date.now() - ts) / 86400000));
  }

  let registrar = null;
  for (const entity of Array.isArray(data.entities) ? data.entities : []) {
    const roles = entity.roles || [];
    if (!roles.includes('registrar')) continue;
    const vcard = (entity.vcardArray && entity.vcardArray[1]) || [];
    const fn = vcard.find((entry) => entry[0] === 'fn');
    if (fn) registrar = fn[3] || null;
    break;
  }

  return {
    found: true,
    via,
    ldhName: data.ldhName || null,
    createdAt,
    expiresAt,
    ageDays,
    registrar,
    statuses: Array.isArray(data.status) ? data.status.slice(0, 6) : []
  };
}

async function checkRdap(domain, options = {}) {
  const headers = { accept: 'application/rdap+json' };

  // Voie 1 : agrégateur rdap.org
  const primary = await fetchJson(`${RDAP_URL}${encodeURIComponent(domain)}`, { headers, timeout: options.timeout });
  if (primary.status === 404) return { found: false, via: 'rdap.org' };
  if (primary.ok && primary.json) return parseRdap(primary.json, 'rdap.org');

  // Voie 2 : registre officiel déclaré par l'IANA pour cette extension
  const apex = registeredDomain(domain) || domain;
  const tld = apex.slice(apex.lastIndexOf('.') + 1).toLowerCase();
  try {
    const bootstrap = await loadBootstrap(options);
    const base = bootstrap && bootstrap.get(tld);
    if (base) {
      const fallback = await fetchJson(`${base}/domain/${encodeURIComponent(apex)}`, { headers, timeout: options.timeout });
      if (fallback.status === 404) return { found: false, via: 'registry' };
      if (fallback.ok && fallback.json) return parseRdap(fallback.json, 'registry');
      return { found: null, error: fallback.error || `registry_http_${fallback.status}` };
    }
  } catch {
    /* on retombe sur l'erreur de la voie 1 */
  }

  return { found: null, error: primary.error || `http_${primary.status}` };
}

/* ------------------------------------------------------------------ *
 * 5. Source 3 — domaines jetables (liste publique, cache 12 h + secours local)
 * ------------------------------------------------------------------ */

let disposableCache = { at: 0, set: null, source: null, size: 0, error: null };

function loadSeedSet() {
  try {
    const text = fs.readFileSync(SEED_LIST_FILE, 'utf8');
    return new Set(
      text
        .split(/\r?\n/)
        .map((line) => line.trim().toLowerCase())
        .filter((line) => line && !line.startsWith('#'))
    );
  } catch {
    return new Set();
  }
}

async function loadDisposableSet(options = {}) {
  const fresh = disposableCache.set && Date.now() - disposableCache.at < LIST_TTL_MS;
  if (fresh && !options.forceRefresh) return disposableCache;

  if (options.offline) {
    const set = loadSeedSet();
    disposableCache = { at: Date.now(), set, source: 'seed', size: set.size, error: null };
    return disposableCache;
  }

  const res = await fetchText(DISPOSABLE_LIST_URL, { timeout: options.timeout || 12000 });
  if (res.ok && res.text) {
    const set = new Set(
      res.text
        .split(/\r?\n/)
        .map((line) => line.trim().toLowerCase())
        .filter((line) => line && !line.startsWith('#'))
    );
    if (set.size >= 100) {
      disposableCache = { at: Date.now(), set, source: 'blocklist', size: set.size, error: null };
      return disposableCache;
    }
  }

  const set = loadSeedSet();
  disposableCache = {
    at: Date.now(),
    set,
    source: 'seed',
    size: set.size,
    error: res.error || `http_${res.status}`
  };
  return disposableCache;
}

async function checkDisposable(domain, options = {}) {
  const list = await loadDisposableSet(options);
  const apex = registeredDomain(domain);
  const candidates = [domain.toLowerCase(), apex].filter(Boolean);

  let matchedOn = null;
  for (const candidate of candidates) {
    if (list.set.has(candidate)) {
      matchedOn = candidate;
      break;
    }
  }

  return {
    listed: matchedOn !== null,
    matchedOn,
    source: list.source, // 'blocklist' (ligne publique) ou 'seed' (secours local)
    listSize: list.size,
    error: list.error
  };
}

/* ------------------------------------------------------------------ *
 * 6. Source 4 — urlscan.io (analyses publiques déjà existantes)
 * ------------------------------------------------------------------ */

async function checkUrlscan(domain, options = {}) {
  const url = `${URLSCAN_SEARCH_URL}?q=${encodeURIComponent(`domain:${domain}`)}&size=10`;
  const res = await fetchJson(url, {
    headers: { accept: 'application/json', 'User-Agent': 'email-domain-security' },
    timeout: options.timeout
  });

  if (res.status === 429) return { error: 'rate_limited' };
  if (!res.ok || !res.json) return { error: res.error || `http_${res.status}` };

  const results = Array.isArray(res.json.results) ? res.json.results : [];
  let maliciousScans = 0;
  let lastScan = null;
  let uniqIPs = null;

  for (const item of results) {
    const verdict = item.verdicts && item.verdicts.overall;
    if (verdict && verdict.malicious === true) maliciousScans += 1;
    const time = item.task && item.task.time;
    if (time && (!lastScan || time > lastScan)) lastScan = time;
    if (uniqIPs === null && item.stats && typeof item.stats.uniqIPs === 'number') uniqIPs = item.stats.uniqIPs;
  }

  return {
    total: typeof res.json.total === 'number' ? res.json.total : results.length,
    sampled: results.length,
    maliciousScans,
    lastScan,
    uniqIPs
  };
}

/* ------------------------------------------------------------------ *
 * 7. Enrichissement optionnel — VirusTotal (clé jamais écrite ici)
 * ------------------------------------------------------------------ */

async function checkVirusTotal(domain, apiKey, options = {}) {
  if (!apiKey) return { enabled: false };

  const res = await fetchJson(`${VT_DOMAIN_URL}${encodeURIComponent(domain)}`, {
    headers: { 'x-apikey': apiKey, accept: 'application/json' },
    timeout: options.timeout || 9000
  });

  if (res.status === 401 || res.status === 403) return { enabled: true, error: 'invalid_key' };
  if (res.status === 429) return { enabled: true, error: 'quota_exceeded' };
  if (res.status === 404) return { enabled: true, found: false };
  if (!res.ok || !res.json) return { enabled: true, error: res.error || `http_${res.status}` };

  const attributes = (res.json.data && res.json.data.attributes) || {};
  const stats = attributes.last_analysis_stats || {};
  const categories = attributes.categories || {};

  return {
    enabled: true,
    found: true,
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    reputation: typeof attributes.reputation === 'number' ? attributes.reputation : null,
    categories: Object.values(categories).slice(0, 5),
    lastAnalysis: attributes.last_analysis_date
      ? new Date(attributes.last_analysis_date * 1000).toISOString()
      : null
  };
}

/* ------------------------------------------------------------------ *
 * 8. Orchestration
 * ------------------------------------------------------------------ */

/**
 * Lance toutes les sources en parallèle et renvoie :
 *  { domain, checkedAt, durationMs, signals, sources }
 * `sources` indique l'état de chaque source : ok | error | disabled.
 * Aucune exception ne remonte.
 */
async function collectSignals(domain, options = {}) {
  const startedAt = Date.now();
  const opts = { timeout: options.timeout || DEFAULT_TIMEOUT, offline: Boolean(options.offline), forceRefresh: Boolean(options.forceRefresh) };
  const apex = registeredDomain(domain) || domain;

  const settled = await Promise.allSettled([
    checkDns(domain, opts),
    checkRdap(apex, opts),
    checkDisposable(domain, opts),
    checkUrlscan(domain, opts),
    checkVirusTotal(domain, options.virustotalKey, opts)
  ]);

  const [dnsRes, rdapRes, disposableRes, urlscanRes, vtRes] = settled;

  const value = (res, fallback) => (res.status === 'fulfilled' && res.value ? res.value : fallback);

  const dns = value(dnsRes, { error: 'unhandled_failure' });
  const rdap = value(rdapRes, { found: null, error: 'unhandled_failure' });
  const disposable = value(disposableRes, { listed: null, error: 'unhandled_failure' });
  const urlscan = value(urlscanRes, { error: 'unhandled_failure' });
  const virustotal = value(vtRes, { enabled: Boolean(options.virustotalKey), error: 'unhandled_failure' });

  const sources = {
    dns: dns.error ? 'error' : 'ok',
    rdap: rdap.found === null ? 'error' : 'ok',
    blocklist: disposable.error && disposable.listed === null ? 'error' : 'ok',
    urlscan: urlscan.error ? 'error' : 'ok',
    virustotal: !virustotal.enabled ? 'disabled' : virustotal.error ? 'error' : 'ok'
  };

  return {
    domain,
    registeredDomain: apex,
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    signals: { dns, rdap, disposable, urlscan, virustotal },
    sources
  };
}

/**
 * Le domaine est-il exploitable ? Utilisé pour distinguer « domaine inexistant »
 * (erreur 404) d'une analyse normale. Renvoie true / false / null (indéterminé).
 */
function domainExists(signals) {
  const dns = signals.dns || {};
  const rdap = signals.rdap || {};
  if (dns.error === 'all_queries_failed' && rdap.found === null) return null;
  if (dns.resolvable === false && rdap.found === false) return false;
  if (dns.hasA || dns.hasNs || dns.hasMx || rdap.found) return true;
  if (dns.resolvable === false) return false;
  return null;
}

module.exports = {
  isValidEmail,
  extractDomain,
  registeredDomain,
  dohQuery,
  checkDns,
  checkRdap,
  loadBootstrap,
  parseRdap,
  checkDisposable,
  loadDisposableSet,
  checkUrlscan,
  checkVirusTotal,
  collectSignals,
  domainExists,
  firstMatch,
  parseSpf,
  parseDmarcPolicy,
  USER_AGENT,
  MULTI_LEVEL_TLDS,
  DISPOSABLE_LIST_URL,
  IANA_BOOTSTRAP_URL
};
