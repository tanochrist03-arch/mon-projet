'use strict';
/**
 * Email Domain Security — test de fumée RÉEL (appels réseau sortants).
 *
 *   node scripts/smoke.js                 -> domaines par défaut
 *   node scripts/smoke.js google.com yopmail.com
 *
 * Sans argument, lance l'analyse complète sur quelques domaines de contrôle et
 * affiche le rapport condensé. Sert à vérifier que les sources externes
 * répondent vraiment (DNS, RDAP, liste de jetables, urlscan).
 */

const { collectSignals, domainExists, registeredDomain } = require('../lib/checks');
const { computeScore } = require('../lib/scoring');

const DEFAULT_DOMAINS = ['google.com', 'entreprise.com', 'yopmail.com', 'domaine-inexistant-zzz-98765.com'];

async function main() {
  const domains = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_DOMAINS;
  const virustotalKey = process.env.VIRUSTOTAL_API_KEY || '';

  console.log(`Sources : dns, rdap, blocklist, urlscan${virustotalKey ? ', virustotal' : ' (virustotal désactivé : aucune clé)'}\n`);

  for (const domain of domains) {
    const started = Date.now();
    const collected = await collectSignals(domain, { virustotalKey });
    const exists = domainExists(collected.signals);
    const scored = exists === false
      ? { score: null, risk: 'UNKNOWN', reputation: 'UNKNOWN', reasons: [{ code: 'DOMAIN_NOT_FOUND', points: 0, label: 'domaine inexistant' }] }
      : computeScore(collected.signals);

    const dns = collected.signals.dns;
    const rdap = collected.signals.rdap;
    const dis = collected.signals.disposable;

    console.log(`───────────────────────────────────────────────────────────`);
    console.log(`${domain}  (domaine enregistré : ${registeredDomain(domain)})`);
    console.log(`  risque      : ${scored.risk}   réputation : ${scored.reputation}   score : ${scored.score}`);
    console.log(`  existe      : ${exists}`);
    console.log(`  MX          : ${dns.error ? 'n/a' : (dns.hasMx ? `${dns.mxCount}${dns.nullMx ? ' (null MX)' : ''}` : 'aucun')}   SPF : ${dns.spf || 'absent'}   DMARC : ${dns.hasDmarc ? 'p=' + dns.dmarcPolicy : 'absent'}`);
    console.log(`  RDAP        : ${rdap.found === true ? `créé le ${rdap.createdAt} (${rdap.ageDays} j), registrar ${rdap.registrar || '?'}` : rdap.found === false ? 'domaine non trouvé' : 'indisponible'}`);
    console.log(`  jetables    : ${dis.listed === true ? `OUI (${dis.matchedOn})` : dis.listed === false ? 'non' : 'indéterminé'}  [source: ${dis.source}, ${dis.listSize} entrées]`);
    console.log(`  urlscan     : ${collected.signals.urlscan.error ? 'indisponible (' + collected.signals.urlscan.error + ')' : collected.signals.urlscan.total + ' analyse(s) publique(s)'}`);
    console.log(`  VT          : ${collected.signals.virustotal.enabled ? JSON.stringify({ malicious: collected.signals.virustotal.malicious, suspicious: collected.signals.virustotal.suspicious }) : 'désactivé'}`);
    console.log(`  sources     : ${Object.entries(collected.sources).map(([k, v]) => `${k}=${v}`).join(' ')}`);
    if (scored.reasons.length) {
      console.log(`  critères    :`);
      for (const reason of scored.reasons) console.log(`     +${reason.points} ${reason.code} — ${reason.label}`);
    }
    console.log(`  durée       : ${Date.now() - started} ms`);
  }
  console.log(`───────────────────────────────────────────────────────────`);
}

main().catch((err) => {
  console.error('Échec du test de fumée :', err);
  process.exit(1);
});
