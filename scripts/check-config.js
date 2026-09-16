'use strict';
/**
 * Email Domain Security — diagnostic de configuration Supabase.
 *
 *   node scripts/check-config.js
 *
 * N'AFFICHE JAMAIS la valeur d'une clé : uniquement sa présence, sa famille
 * (préfixe) et sa longueur. Ne se connecte à rien, ne modifie rien.
 * Utilise exactement le même code de lecture que l'application
 * (lib/supabase.js -> supabaseConfig), donc ce diagnostic dit la vérité sur ce
 * que verra api/analyze.js en production ou en local.
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

/* Même ordre de chargement que scripts/dev-server.js */
for (const file of ['.env.local', '.env']) {
  loadEnvFile(path.join(ROOT, file));
}

function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    const key = match[1];
    const value = match[2].trim().replace(/^["']|["']$/g, '');
    if (process.env[key] === undefined) process.env[key] = value;
  }
}

const MASK = '<valeur masquée>';

/** Décrit un secret sans le révéler : famille + longueur. */
function describeKey(value) {
  if (!value) return 'absente';
  const length = value.length;
  if (value.startsWith('sb_secret_')) return `clé secrète Supabase (sb_secret_…), longueur ${length}`;
  if (value.startsWith('sb_publishable_')) return `clé PUBLIQUE Supabase (sb_publishable_…), longueur ${length} — inadaptée à une écriture serveur`;
  if (value.startsWith('eyJ')) {
    let role = 'indéterminé';
    try {
      const payload = JSON.parse(Buffer.from(value.split('.')[1], 'base64').toString('utf8'));
      role = payload.role || 'indéterminé';
    } catch {
      /* payload illisible : on ne dit rien de plus */
    }
    return `JWT (ancien format), rôle déclaré : ${role}, longueur ${length}`;
  }
  return `format non reconnu, longueur ${length}`;
}

/** Vérifie la forme d'une URL sans l'afficher. */
function describeUrl(value) {
  if (!value) return 'absente';
  if (/^https:\/\/[a-z0-9]{15,30}\.supabase\.co\/?$/.test(value)) return 'forme conforme : https://<ref>.supabase.co';
  if (/^https:\/\/(www\.)?supabase\.com\/?$/.test(value)) return 'INCORRECTE : c’est l’URL du site Supabase, pas celle de l’API du projet';
  if (/^https?:\/\//.test(value)) return 'hôte inattendu pour un projet Supabase';
  return 'INCORRECTE : ce n’est pas une URL absolue (https://…)';
}

const { supabaseConfig } = require('../lib/supabase');

function main() {
  const url = process.env.SUPABASE_URL || '';
  const secret = process.env.SUPABASE_SECRET_KEY || '';
  const serviceRole = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

  console.log('=== Variables attendues (serveur uniquement) ===');
  console.log(`SUPABASE_URL            : ${url ? describeUrl(url) : 'absente'}`);
  console.log(`SUPABASE_SECRET_KEY     : ${describeKey(secret)}`);
  console.log(`SUPABASE_SERVICE_ROLE_KEY (repli, facultatif) : ${describeKey(serviceRole)}`);

  console.log('\n=== Variables actuellement lues par le diagnostic ===');
  console.log(`SUPABASE_URL            : ${url ? 'définie' : 'MANQUANTE'}  ${MASK}`);
  console.log(`SUPABASE_SECRET_KEY     : ${secret ? 'définie' : 'MANQUANTE'}  ${MASK}`);

  console.log('\n=== Variables héritées (côté navigateur, ne doivent plus servir) ===');
  const legacyUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const legacyKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  console.log(`NEXT_PUBLIC_SUPABASE_URL      : ${legacyUrl ? 'présente (obsolète, ignorée par le code)' : 'absente'}`);
  console.log(`NEXT_PUBLIC_SUPABASE_ANON_KEY : ${legacyKey ? `présente (obsolète, ignorée) — ${describeKey(legacyKey)}` : 'absente'}`);

  console.log('\n=== Variables optionnelles ===');
  console.log(`VIRUSTOTAL_API_KEY      : ${process.env.VIRUSTOTAL_API_KEY ? describeKey(process.env.VIRUSTOTAL_API_KEY) : 'absente (facultatif : l’application fonctionne sans)'}`);

  const config = supabaseConfig();
  console.log('\n=== Verdict (code réellement utilisé par api/analyze.js) ===');
  console.log(`Enregistrement Supabase opérationnel : ${config.configured ? 'OUI' : 'NON'}`);

  const problems = [];
  if (!url) problems.push('SUPABASE_URL manquante');
  if (!secret && !serviceRole) problems.push('SUPABASE_SECRET_KEY manquante');
  if (url && /supabase\.com/.test(url)) problems.push('SUPABASE_URL pointe vers le site Supabase au lieu de l’API du projet');
  if (url && !/^https:\/\/[a-z0-9]{15,30}\.supabase\.co\/?$/.test(url)) problems.push('SUPABASE_URL a une forme inattendue');
  if (secret && secret.startsWith('sb_publishable_')) problems.push('SUPABASE_SECRET_KEY contient une clé PUBLIQUE : l’écriture échouera');
  if (secret && secret.startsWith('eyJ')) {
    let role = null;
    try {
      role = JSON.parse(Buffer.from(secret.split('.')[1], 'base64').toString('utf8')).role;
    } catch {
      /* ignore */
    }
    if (role === 'anon') problems.push('SUPABASE_SECRET_KEY contient un JWT anon : insuffisant pour écrire');
  }

  if (problems.length === 0) {
    console.log('Diagnostic global : configuration OK');
  } else {
    console.log('Diagnostic global : éléments manquants ou incorrects');
    for (const problem of problems) console.log(`  - ${problem}`);
    console.log('  À configurer dans Vercel -> Settings -> Environment Variables (Production et Preview),');
    console.log('  et, pour les tests locaux, dans le fichier .env.local du projet.');
  }

  console.log('\nAucune valeur de clé n’a été affichée. Aucune connexion réseau, aucune écriture.');
}

main();
