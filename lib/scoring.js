'use strict';
/**
 * Email Domain Security
 * Barème de risque : traduit des SIGNAUX OBJECTIFS en score 0-100 puis en
 * niveau LOW / MEDIUM / HIGH. Chaque point attribué est renvoyé dans `reasons`
 * pour être affiché dans le rapport et auditable.
 *
 * Aucune E/S, aucune dépendance : module pur, donc entièrement testable.
 *
 * Critères détaillés : voir docs/email-domain-security.md (§ Barème de risque).
 */

const WEIGHTS = Object.freeze({
  DISPOSABLE_LISTED: 60, // domaine figurant dans la liste des domaines jetables
  NO_MX: 25, // aucun MX : le domaine ne peut pas recevoir d'email
  DOMAIN_AGE_30: 30, // domaine créé il y a moins de 30 jours
  DOMAIN_AGE_90: 20, // moins de 90 jours
  DOMAIN_AGE_365: 10, // moins d'un an
  SPF_MISSING: 10, // pas de SPF : usurpation d'expéditeur possible
  SPF_SOFTFAIL: 5, // SPF ~all
  SPF_PASS_ALL: 15, // SPF +all : tout le monde est autorisé
  DMARC_MISSING: 10, // pas de politique anti-usurpation
  DMARC_NONE: 5, // p=none : observation seule
  DMARC_QUARANTINE: 2, // p=quarantine
  VT_MALICIOUS_3: 45, // VirusTotal : >= 3 moteurs malveillants (si clé fournie)
  VT_MALICIOUS_ANY: 15, // VirusTotal : 1-2 moteurs malveillants
  VT_SUSPICIOUS_2: 20, // VirusTotal : >= 2 moteurs suspicieux
  URLSCAN_MALICIOUS: 10 // urlscan.io : analyses publiques au verdict malveillant
});

const THRESHOLDS = Object.freeze({
  LOW_MAX: 24, // 0-24   -> LOW
  MEDIUM_MAX: 59, // 25-59  -> MEDIUM
  HIGH_MIN: 60 // 60-100 -> HIGH
});

const RISK_LEVELS = Object.freeze(['LOW', 'MEDIUM', 'HIGH']);
const REPUTATIONS = Object.freeze(['GOOD', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN']);
const SCORING_VERSION = 'email-domain-security-1.0';

/** Motifs qui déclenchent une réputation MALICIOUS quel que soit le score. */
const HARD_FAIL_CODES = Object.freeze(['DISPOSABLE_LISTED', 'VT_MALICIOUS_3']);

/**
 * @param {{dns?:object, rdap?:object, disposable?:object, urlscan?:object, virustotal?:object}} signals
 * @returns {{score:number, risk:string, reputation:string, reasons:Array, warnings:Array,
 *            hardFail:boolean, rawScore:number, scoringVersion:string}}
 */
function computeScore(signals = {}) {
  const dns = signals.dns || {};
  const rdap = signals.rdap || {};
  const disposable = signals.disposable || {};
  const urlscan = signals.urlscan || {};
  const vt = signals.virustotal || {};

  const reasons = [];
  const warnings = [];

  const add = (code, label, points) => {
    if (points > 0) reasons.push({ code, label, points });
  };

  // Si TOUT le DNS a échoué, on n'invente rien : on avertit et on n'impute aucun
  // des critères DNS (sinon un simple timeout ferait passer un bon domaine en risque élevé).
  const dnsUsable = !dns.error;
  if (!dnsUsable) {
    warnings.push({
      code: 'DNS_UNAVAILABLE',
      label: 'DNS indisponible : MX, SPF et DMARC n’ont pas pu être évalués.'
    });
  }

  // Une requête DNS qui a échoué (timeout, coupure) ne veut PAS dire « absent ».
  // Sans cette précaution, une simple panne réseau ajouterait +25 (aucun MX) ou
  // +10 (SPF absent) à un domaine parfaitement sain.
  const mxKnown = dnsUsable && dns.mxKnown !== false;
  const spfKnown = dnsUsable && dns.txtKnown !== false;
  const dmarcKnown = dnsUsable && dns.dmarcKnown !== false;
  if (dnsUsable && !mxKnown) {
    warnings.push({ code: 'DNS_MX_UNAVAILABLE', label: 'La réponse MX n’a pas pu être obtenue : le test de réception d’email est neutralisé pour cette analyse.' });
  }
  if (dnsUsable && !spfKnown) {
    warnings.push({ code: 'DNS_SPF_UNAVAILABLE', label: 'La réponse SPF n’a pas pu être obtenue : ce critère est neutralisé pour cette analyse.' });
  }
  if (dnsUsable && !dmarcKnown) {
    warnings.push({ code: 'DNS_DMARC_UNAVAILABLE', label: 'La réponse DMARC n’a pas pu être obtenue : ce critère est neutralisé pour cette analyse.' });
  }

  // 1. Domaine jetable
  if (disposable.listed === true) {
    add(
      'DISPOSABLE_LISTED',
      `Domaine jetable connu${disposable.matchedOn ? ` (${disposable.matchedOn})` : ''} — usage typique : inscription à usage unique, spam`,
      WEIGHTS.DISPOSABLE_LISTED
    );
  }

  // 2. MX / SPF / DMARC
  if (dnsUsable) {
    if (mxKnown && dns.hasMx === false) {
      add(
        'NO_MX',
        dns.nullMx
          ? 'Aucun MX exploitable (le domaine publie un « null MX ») : il ne peut pas recevoir d’email'
          : 'Aucun enregistrement MX : le domaine ne peut pas recevoir d’email',
        WEIGHTS.NO_MX
      );
    }
    if (spfKnown && dns.hasSpf === false) {
      add('SPF_MISSING', 'SPF absent : n’importe quel serveur peut usurper ce domaine', WEIGHTS.SPF_MISSING);
    } else if (spfKnown && dns.spfAll === '+all') {
      add('SPF_PASS_ALL', 'SPF réglé sur +all : tous les serveurs sont déclarés autorisés', WEIGHTS.SPF_PASS_ALL);
    } else if (spfKnown && dns.spfAll === '~all') {
      add('SPF_SOFTFAIL', 'SPF réglé sur ~all : expéditeurs non autorisés tolérés', WEIGHTS.SPF_SOFTFAIL);
    }
    if (dmarcKnown && dns.hasDmarc === false) {
      add('DMARC_MISSING', 'DMARC absent : aucune politique anti-usurpation publiée', WEIGHTS.DMARC_MISSING);
    } else if (dmarcKnown && dns.dmarcPolicy === 'none') {
      add('DMARC_NONE', 'DMARC en p=none : observation seulement, aucune protection réelle', WEIGHTS.DMARC_NONE);
    } else if (dmarcKnown && dns.dmarcPolicy === 'quarantine') {
      add('DMARC_QUARANTINE', 'DMARC en p=quarantine : protection intermédiaire', WEIGHTS.DMARC_QUARANTINE);
    }
  }

  // 3. Âge du domaine (RDAP)
  if (typeof rdap.ageDays === 'number' && rdap.ageDays >= 0) {
    if (rdap.ageDays < 30) {
      add('DOMAIN_AGE_30', `Domaine créé il y a ${rdap.ageDays} jour(s) : très récent`, WEIGHTS.DOMAIN_AGE_30);
    } else if (rdap.ageDays < 90) {
      add('DOMAIN_AGE_90', `Domaine créé il y a ${rdap.ageDays} jours : récent`, WEIGHTS.DOMAIN_AGE_90);
    } else if (rdap.ageDays < 365) {
      add('DOMAIN_AGE_365', `Domaine de moins d’un an (${rdap.ageDays} jours)`, WEIGHTS.DOMAIN_AGE_365);
    }
  }

  // 4. VirusTotal (uniquement si une clé a été fournie)
  if (vt.enabled) {
    if (typeof vt.malicious === 'number' && vt.malicious >= 3) {
      add('VT_MALICIOUS_3', `VirusTotal : ${vt.malicious} moteurs signalent le domaine comme malveillant`, WEIGHTS.VT_MALICIOUS_3);
    } else if (typeof vt.malicious === 'number' && vt.malicious > 0) {
      add('VT_MALICIOUS_ANY', `VirusTotal : ${vt.malicious} moteur(s) signalent le domaine`, WEIGHTS.VT_MALICIOUS_ANY);
    }
    if (typeof vt.suspicious === 'number' && vt.suspicious >= 2) {
      add('VT_SUSPICIOUS_2', `VirusTotal : ${vt.suspicious} moteurs le jugent suspect`, WEIGHTS.VT_SUSPICIOUS_2);
    }
  }

  // 5. urlscan.io (signal mineur, plafonné)
  if (typeof urlscan.maliciousScans === 'number' && urlscan.maliciousScans > 0) {
    add(
      'URLSCAN_MALICIOUS',
      `urlscan.io : ${urlscan.maliciousScans} analyse(s) publique(s) avec un verdict malveillant`,
      WEIGHTS.URLSCAN_MALICIOUS
    );
  }

  const rawScore = reasons.reduce((total, reason) => total + reason.points, 0);
  const score = Math.max(0, Math.min(100, rawScore));

  let risk;
  if (score <= THRESHOLDS.LOW_MAX) risk = 'LOW';
  else if (score <= THRESHOLDS.MEDIUM_MAX) risk = 'MEDIUM';
  else risk = 'HIGH';

  const hardFail = reasons.some((reason) => HARD_FAIL_CODES.includes(reason.code));

  // Un domaine présent sur une liste de jetables, ou signalé par >= 3 moteurs,
  // est classé HIGH même si le score cumulé restait sous le seuil : ces deux
  // signaux sont considérés comme rédhibitoires (voir docs/email-domain-security.md).
  if (hardFail) risk = 'HIGH';

  // Combien de sources ont réellement répondu ? Sert à distinguer
  // « domaine propre » de « on ne sait rien ».
  const usableSources = [
    dnsUsable,
    rdap.found !== null && rdap.found !== undefined,
    disposable.error ? false : disposable.listed !== undefined && disposable.listed !== null
  ].filter(Boolean).length;

  let reputation;
  if (hardFail) reputation = 'MALICIOUS';
  else if (risk !== 'LOW') reputation = 'SUSPICIOUS';
  else if (usableSources >= 2) reputation = 'GOOD';
  else reputation = 'UNKNOWN';

  return {
    score,
    risk,
    reputation,
    reasons: reasons.sort((a, b) => b.points - a.points),
    warnings,
    hardFail,
    rawScore,
    scoringVersion: SCORING_VERSION
  };
}

module.exports = {
  computeScore,
  WEIGHTS,
  THRESHOLDS,
  RISK_LEVELS,
  REPUTATIONS,
  HARD_FAIL_CODES,
  SCORING_VERSION
};
