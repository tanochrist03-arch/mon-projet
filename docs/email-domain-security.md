# Email Domain Security

Analyse de la sécurité d'un **domaine email professionnel** : on saisit une adresse,
le domaine est extrait, interrogé auprès de plusieurs sources, noté
**LOW / MEDIUM / HIGH**, puis le rapport est enregistré dans Supabase.

Application hébergée sur **Vercel** (fonctions serverless) + **Supabase** (PostgreSQL).
Aucune étape de build, aucune dépendance supplémentaire (Node 20+ requis).

---

## 1. Utilisation

### En production (Vercel)
| Route | Méthode | Rôle |
|---|---|---|
| `/` | GET | Interface **Email Domain Security** (formulaire, rapport, historique) |
| `/api/analyze` | GET | Informations sur l'application (nom, version, sources actives) |
| `/api/analyze` | POST | `{ "email": "contact@entreprise.com" }` → rapport complet |
| `/api/analyze?email=...` | GET | Même analyse, pratique pour tester en ligne de commande |
| `/api/history` | GET | Analyses enregistrées : `?limit=10&offset=0&q=google` (recherche par domaine ou email) |

### En local (sans npm, sans Vercel CLI)
```bash
node scripts/dev-server.js          # http://localhost:3000
node scripts/dev-server.js 4000     # autre port
node scripts/smoke.js               # test de fumée réseau réel
node --test tests/                  # tests unitaires (aucun réseau)
```

Exemple d'appel direct :
```bash
curl -s -X POST http://localhost:3000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"email":"contact@entreprise.com"}'
```

---

## 2. Architecture

```
Navigateur (index.html : formulaire + rapport)
   │  POST /api/analyze  { email }
   ▼
api/analyze.js  (Vercel, runtime Node, côté serveur)
   ├─ lib/checks.js     collecte : DNS-over-HTTPS · RDAP · domaines jetables · urlscan · [VirusTotal]
   ├─ lib/scoring.js    barème -> score 0-100 -> LOW / MEDIUM / HIGH
   └─ lib/supabase.js   enregistrement PostgREST avec la clé SECRÈTE (serveur uniquement)
   ▼
public.domain_analyses  (RLS activé, aucune politique publique)
```

Points clés de sécurité :
- **aucune clé dans le navigateur** : `index.html` ne contacte plus Supabase directement ;
- la clé Supabase vit dans `process.env` (Vercel → Environment Variables) et n'est
  jamais écrite dans le code, ni loguée, ni renvoyée dans une réponse (fonction `sanitize`) ;
- les variables sont nommées **sans** préfixe `NEXT_PUBLIC_` pour ne pas être inlinées
  dans le bundle navigateur ;
- le RLS reste **fermé** : la clé secrète serveur est la seule voie d'accès ;
- un test automatisé (`tests/secrets.test.js`) échoue si un secret apparaît dans un fichier livré.

---

## 3. Sources de données

| Source | Clé requise | Données | Limites connues |
|---|---|---|---|
| Google DNS-over-HTTPS (`dns.google`) | non | MX, TXT/SPF, `_dmarc`, A, NS | aucune limite pratique |
| RDAP (`rdap.org`) | non | date de création, expiration, registrar, statuts | certains TLD répondent partiellement |
| Liste publique de domaines jetables | non | ~8 800 domaines, cache 12 h | liste communautaire, non exhaustive |
| urlscan.io (`/api/v1/search`) | non | analyses publiques existantes | quota non documenté, 429 géré |
| VirusTotal v3 (optionnel) | **oui** | verdict de 90+ moteurs, catégories, réputation | 500 req/jour, 4/min (API publique) |

Fonctionnement **sans VirusTotal** : si `VIRUSTOTAL_API_KEY` est absente, la source est
marquée `disabled` et le score est calculé sur les autres. Aucune erreur, aucun ralentissement.

La liste des domaines jetables est mise en cache 12 h. Si elle est injoignable, la liste
locale `data/disposable-seed.txt` prend le relais (le champ `signals.disposable.source`
indique `blocklist` ou `seed`, pour rester transparent).

---

## 4. Barème de risque (critères objectifs)

Score cumulé de 0 à 100, chaque point attribué est listé dans le rapport (`reasons`).

| Critère | Condition | Points |
|---|---|---|
| `DISPOSABLE_LISTED` | domaine présent dans la liste des jetables | **+60** *(rédhibitoire)* |
| `NO_MX` | aucun MX exploitable (ou « null MX ») → ne peut pas recevoir d'email | +25 |
| `DOMAIN_AGE_30` | créé il y a moins de 30 jours (RDAP) | +30 |
| `DOMAIN_AGE_90` | moins de 90 jours | +20 |
| `DOMAIN_AGE_365` | moins d'un an | +10 |
| `SPF_MISSING` | SPF absent | +10 |
| `SPF_PASS_ALL` | SPF `+all` | +15 |
| `SPF_SOFTFAIL` | SPF `~all` | +5 |
| `DMARC_MISSING` | DMARC absent | +10 |
| `DMARC_NONE` | `p=none` (observation seule) | +5 |
| `DMARC_QUARANTINE` | `p=quarantine` | +2 |
| `VT_MALICIOUS_3` | VirusTotal : ≥ 3 moteurs malveillants | **+45** *(rédhibitoire)* |
| `VT_MALICIOUS_ANY` | VirusTotal : 1-2 moteurs | +15 |
| `VT_SUSPICIOUS_2` | VirusTotal : ≥ 2 moteurs suspicieux | +20 |
| `URLSCAN_MALICIOUS` | urlscan.io : analyse publique au verdict malveillant | +10 |

**Conversion du score :**
- `0 – 24` → **LOW**
- `25 – 59` → **MEDIUM**
- `60 – 100` → **HIGH**

**Critères rédhibitoires** : un domaine jetable connu, ou signalé par ≥ 3 moteurs
VirusTotal, est classé **HIGH** avec une réputation **MALICIOUS** même si la somme
des points restait sous le seuil.

**Réputation** : `MALICIOUS` (critère rédhibitoire) · `SUSPICIOUS` (risque MEDIUM ou HIGH) ·
`GOOD` (risque LOW avec au moins 2 sources exploitables) · `UNKNOWN` (pas assez de données).

**Cas particuliers honnêtes :**
- **DNS entièrement indisponible** : aucun critère MX/SPF/DMARC n'est imputé (sinon une
  simple panne ferait passer un domaine sain en risque élevé) ; un avertissement
  `DNS_UNAVAILABLE` est ajouté au rapport.
- **Domaine inexistant** (NXDOMAIN + absent du RDAP) : HTTP 404, `risk = UNKNOWN`,
  `risk_score = null`, et l'analyse est **quand même enregistrée** en base.
- Un domaine peut cumuler plusieurs critères : le score est plafonné à 100.

---

## 5. Base de données

Table `public.domain_analyses` — script `sql/001_domain_analyses.sql`
(**non exécuté automatiquement : à lancer manuellement dans Supabase → SQL Editor,
après validation**).

| Colonne | Type | Rôle |
|---|---|---|
| `id` | uuid | clé primaire |
| `created_at` | timestamptz | date/heure de l'analyse |
| `email` | text | adresse analysée (donnée personnelle) |
| `domain` | text | domaine extrait |
| `reputation` | text | GOOD / SUSPICIOUS / MALICIOUS / UNKNOWN |
| `risk` | text | LOW / MEDIUM / HIGH / UNKNOWN |
| `risk_score` | integer | score 0-100 (`null` si UNKNOWN) |
| `reasons` | jsonb | critères déclenchés et leur poids |
| `signals` | jsonb | données brutes (dns, rdap, disposable, urlscan, virustotal) |
| `sources` | text[] | état par source : ok / error / disabled |
| `duration_ms` | integer | durée de l'analyse |
| `app_version` | text | version du moteur de scoring |

### RLS
Le script active `row level security`, **ne crée aucune politique** et retire
explicitement les droits à `anon` et `authenticated`. Conséquence : la clé publique
ne peut rien lire ni écrire, tandis que la clé secrète serveur écrit normalement.

Vérification (lecture seule), avec une clé **anon** — la réponse ne doit **jamais** contenir de lignes.
Deux réponses acceptables, selon que le rôle `anon` a conservé des privilèges ou non :
```
permission denied for table domain_analyses   (code 42501)   <- cas normal ici, le script a révoqué les droits
[]                                                           <- si le RLS seul bloque
```
```bash
curl "https://VOTRE-PROJET.supabase.co/rest/v1/domain_analyses?select=*" -H "apikey: VOTRE_CLE_ANON"
```
Toute autre réponse contenant des données signale une exposition à corriger immédiatement.

> Données personnelles : la colonne `email` en contient. Prévoir une purge régulière
> (exemple dans le script SQL : suppression au-delà de 12 mois).

---

## 6. Variables d'environnement

| Variable | Obligatoire | Rôle |
|---|---|---|
| `SUPABASE_URL` | oui (pour l'enregistrement) | URL de l'API du projet Supabase |
| `SUPABASE_SECRET_KEY` | oui (pour l'enregistrement) | clé secrète serveur (`sb_secret_...` ou `service_role`) |
| `VIRUSTOTAL_API_KEY` | non | active l'enrichissement VirusTotal |
| `EDS_OFFLINE` | non | `1` = liste locale de domaines jetables uniquement |
| `TELEGRAM_BOT_TOKEN` | — | bot Telegram existant (`api/bot.js`, inchangé) |
| `DEEPSEEK_API_KEY` | — | bot Telegram existant (`api/bot.js`, inchangé) |

Sans `SUPABASE_URL` / `SUPABASE_SECRET_KEY`, **l'analyse fonctionne quand même** :
la réponse contient `saved: false` et `save_error: "not_configured"`.

Sur Vercel : Settings → Environment Variables. En local : `.env.local` (ignoré par Git).

---

## 7. Gestion des erreurs

| Situation | Comportement |
|---|---|
| Email invalide | HTTP 400, `code: "INVALID_EMAIL"`, rien n'est enregistré |
| Corps JSON invalide | HTTP 400, `code: "INVALID_BODY"` |
| Méthode non supportée | HTTP 405, `code: "METHOD_NOT_ALLOWED"` |
| Domaine inexistant | HTTP 404, `code: "DOMAIN_NOT_FOUND"`, rapport `UNKNOWN` enregistré |
| Source tierce indisponible / quota | dégradation : source marquée `error`, score calculé sur le reste |
| Liste de jetables injoignable | repli sur `data/disposable-seed.txt` (`source: "seed"`) |
| Supabase non configuré | rapport renvoyé avec `saved: false`, `save_error: "not_configured"` |
| Supabase en erreur (401, quota, réseau) | rapport renvoyé avec `saved: false`, erreur nettoyée des secrets |

---

## 8. Tests

```bash
node --test          # 86 tests, aucun appel réseau
```

- `tests/scoring.test.js` — barème : chaque poids, chaque seuil, plafonnement,
  rédhibitoires, panne DNS totale, réputation UNKNOWN.
- `tests/checks.test.js` — validation email, extraction et domaine enregistré,
  parsing DNS/RDAP/urlscan/VirusTotal, null MX, NXDOMAIN, repli liste locale,
  User-Agent obligatoire et repli vers le registre RDAP officiel.
- `tests/analyze.test.js` — endpoint d'analyse : 400/404/405, dégradation,
  enregistrement, non-exposition des secrets dans la réponse.
- `tests/history.test.js` — pagination, recherche (et son nettoyage), total,
  page hors limites, erreurs, non-exposition des secrets.
- `tests/schema.test.js` — **contrat SQL ↔ JavaScript** : colonnes, contraintes,
  index, RLS activé, aucune politique publique, idempotence.
- `tests/secrets.test.js` — aucun secret en dur, frontend sans Supabase,
  `api/bot.js` intact, nom officiel partout, éléments d'interface présents.
- `scripts/smoke.js` — test de fumée **réel** sur des domaines de contrôle.
- `scripts/check-config.js` — diagnostic de configuration (n'affiche jamais une clé).

---

## 9. Notes d'implémentation

- `@supabase/supabase-js` reste déclaré dans `package.json` (utilisé nulle part ici :
  l'accès passe par `fetch` vers PostgREST, ce qui évite toute dépendance nouvelle et
  garde le code testable sans installation). Il peut être retiré si tu le souhaites.
- `api/bot.js` **n'a pas été modifié** par le Email Domain Security.
- Pas de `vercel.json` : Vercel détecte automatiquement les fichiers de `api/`.
