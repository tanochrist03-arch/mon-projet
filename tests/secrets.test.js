'use strict';
/**
 * Email Domain Security — garde-fou secrets.
 * Vérifie qu'aucune clé, aucun token et aucune URL de projet ne se trouve dans
 * les fichiers livrés (et notamment dans index.html, qui part chez le navigateur).
 * Lancement : node --test tests/
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

/** Fichiers qui partent chez le client / sur GitHub. */
const DELIVERED_FILES = [
  'index.html',
  'assets/logo.svg',
  'assets/favicon.svg',
  'api/analyze.js',
  'api/history.js',
  'lib/checks.js',
  'lib/scoring.js',
  'lib/supabase.js',
  'scripts/dev-server.js',
  'scripts/smoke.js',
  'scripts/check-config.js',
  '.env.example',
  'sql/001_domain_analyses.sql',
  'package.json'
];

const FORBIDDEN = [
  [/sb_secret_[A-Za-z0-9_-]{8,}/, 'clé secrète Supabase'],
  [/sb_publishable_[A-Za-z0-9_-]{8,}/, 'clé publishable Supabase'],
  [/eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, 'JWT (ancienne clé anon/service)'],
  [/bot\d{8,}:[A-Za-z0-9_-]{25,}/, 'token de bot Telegram'],
  [/AIza[A-Za-z0-9_-]{20,}/, 'clé API Google'],
  [/sk-[A-Za-z0-9]{20,}/, 'clé API de type OpenAI/DeepSeek'],
  [/[a-z0-9]{20}\.supabase\.co/, 'URL de projet Supabase']
];

function read(relative) {
  const file = path.join(ROOT, relative);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
}

test('aucun secret en dur dans les fichiers livrés', () => {
  for (const relative of DELIVERED_FILES) {
    const content = read(relative);
    if (content === null) continue; // fichiers optionnels
    for (const [pattern, label] of FORBIDDEN) {
      assert.equal(pattern.test(content), false, `${label} détecté dans ${relative}`);
    }
  }
});

test('index.html ne parle plus directement à Supabase', () => {
  const html = read('index.html');
  assert.ok(html.includes('/api/analyze'), 'la page doit passer par l’API serverless');
  assert.equal(/supabase\.co/.test(html), false, 'aucune URL Supabase ne doit figurer dans le frontend');
  assert.equal(/supabaseKey|createClient/.test(html), false, 'aucun client Supabase dans le frontend');
  assert.equal(/NEXT_PUBLIC_/.test(html), false, 'aucune variable publique Supabase dans le frontend');
});

test('api/bot.js est intact et lit toujours ses secrets dans l’environnement', () => {
  const bot = read('api/bot.js');
  assert.ok(bot, 'api/bot.js doit exister');
  assert.ok(bot.includes('process.env.TELEGRAM_BOT_TOKEN'), 'le token Telegram doit venir de l’environnement');
  assert.equal(/bot\d{8,}:/.test(bot), false);
});

test('.env.example ne contient que des valeurs factices', () => {
  const example = read('.env.example');
  assert.ok(/SUPABASE_URL=/.test(example), 'la variable SUPABASE_URL doit être documentée');
  assert.ok(/SUPABASE_SECRET_KEY=/.test(example), 'la variable SUPABASE_SECRET_KEY doit être documentée');
  assert.ok(/VIRUSTOTAL_API_KEY=/.test(example), 'la variable VIRUSTOTAL_API_KEY doit être documentée');
  assert.equal(/remplace_moi|^[A-Z_]+=.+[A-Za-z0-9]{20,}$/m.test(example.replace(/remplace_moi/g, '')), false, 'aucune valeur réelle dans .env.example');
});

test('le nom officiel est utilisé partout, l’ancien nom a disparu', () => {
  for (const relative of ['index.html', 'api/analyze.js', 'api/history.js', 'lib/checks.js', 'lib/scoring.js', 'lib/supabase.js', '.env.example', 'package.json']) {
    const content = read(relative);
    if (content === null) continue;
    assert.equal(/projet\s*9/i.test(content), false, `ancien nom de projet détecté dans ${relative}`);
  }
  const html = read('index.html');
  assert.match(html, /<title>Email Domain Security<\/title>/, 'le titre HTML doit être le nom officiel');
  assert.match(html, /Email Domain Security 1\.0/, 'la version affichée doit être Email Domain Security 1.0');
  assert.match(html, /Saisissez une adresse email professionnelle pour analyser la réputation et les signaux de sécurité de son domaine\./, 'sous-titre officiel attendu');
  assert.match(html, /Analysez la sécurité d’un/, 'titre principal attendu');
  assert.match(html, /Saisissez une adresse email professionnelle/, 'libellé du champ attendu');
  assert.match(html, /Analyser le domaine/, 'libellé du bouton principal attendu');
});

test('l’interface expose les éléments clés demandés (score, risque, réputation, une carte par signal)', () => {
  const html = read('index.html');
  for (const label of ['Score de risque', 'Risque', 'Réputation', 'DNS', 'MX', 'SPF', 'DMARC', 'RDAP', 'Domaine jetable', 'urlscan.io', 'VirusTotal', 'Nouvelle analyse']) {
    assert.ok(html.includes(label), `élément d’interface manquant : ${label}`);
  }
  assert.match(html, /sourceChip\('DNS'[\s\S]{0,140}sourceChip\('RDAP'/, 'chaque source doit avoir sa propre pastille');
  assert.match(html, /disabled: \{ cls: 'disabled'/, 'VirusTotal doit pouvoir s’afficher comme désactivé');
  assert.match(html, /LOW<\/b> 0–24/, 'les seuils doivent être affichés');
  assert.match(html, /VirusTotal — Désactivé/, 'l’état désactivé de VirusTotal doit être explicite');
  assert.equal(/dns : okrdap/.test(html), false, 'les sources ne doivent pas être collées');
});

test('l’historique a disparu de l’interface (ni page, ni menu, ni section)', () => {
  const html = read('index.html');
  assert.equal(/historique/i.test(html), false, 'aucune mention d’historique ne doit subsister dans l’interface');
  assert.equal(html.includes('/api/history'), false, 'l’interface ne doit plus appeler /api/history');
  assert.equal(/<table/.test(html), false, 'plus de tableau d’analyses dans l’interface');
});

test('le logo est un SVG local, sans ressource externe', () => {
  for (const file of ['assets/logo.svg', 'assets/favicon.svg']) {
    const svg = read(file);
    assert.ok(svg, `${file} doit exister`);
    assert.ok(svg.includes('<svg'), `${file} doit être un SVG`);
    assert.ok(svg.includes('viewBox'), `${file} doit être redimensionnable`);
    assert.equal(/<script/i.test(svg), false, `${file} ne doit contenir aucun script`);
    assert.equal(/https?:\/\//.test(svg.replace(/xmlns="http:\/\/www\.w3\.org\/2000\/svg"/g, '')), false, `${file} ne doit référencer aucune ressource externe`);
  }
  const html = read('index.html');
  assert.ok(html.includes('assets/logo.svg'), 'le header doit utiliser le logo');
  assert.ok(html.includes('assets/favicon.svg'), 'le favicon doit pointer vers le SVG');
});

test('.gitignore protège les fichiers d’environnement', () => {
  const ignore = read('.gitignore');
  assert.ok(/^\.env\*?$/m.test(ignore) || /^\.env\.\*$/m.test(ignore) || /^\.env$/m.test(ignore), 'les fichiers .env doivent être ignorés');
});
