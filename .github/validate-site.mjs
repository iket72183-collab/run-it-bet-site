#!/usr/bin/env node
/**
 * Checks a built copy of the public static site before it can go live.
 *
 *   node scripts/validate-site.mjs <site-dir> [--origin https://www.runitbet.com]
 *
 * Run twice on every publication: by scripts/publish-static.mjs before it commits (nothing is
 * pushed if this fails), and by the site repo's own CI on every pushed commit (Render deploys only
 * after that check passes). The site repo keeps a byte-identical copy at .github/validate-site.mjs,
 * so this file must stay self-contained: Node built-ins only, no imports from this repo.
 *
 * It fails closed on: a missing expected file; any file outside the known public layout (so .env,
 * keys, databases, source maps, logs or source code can't ride along); credential-shaped text or
 * internal addresses; public JSON that doesn't match its shape or still carries private fields; an
 * outbound link that isn't https on an allowed host; and executable scripts the CSP would block.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const DEFAULT_ORIGIN = 'https://www.runitbet.com';

const STATIC_PAGES = ['agents', 'how-we-pick', 'legal', 'responsible-gaming', 'settings'];
const REQUIRED = ['index.html', '404.html', 'robots.txt', 'sitemap.xml', 'favicon.svg', '.build-commit',
  'api/board.json', 'api/agent/today.json', ...STATIC_PAGES.map((p) => `${p}/index.html`)];

// Every path the publisher may produce. Anything else is rejected, whatever it contains.
const ALLOWED_PATHS = [
  /^(index|404)\.html$/,
  /^(robots\.txt|sitemap\.xml|\.nojekyll|\.build-commit)$/,
  /^[A-Za-z0-9._-]+\.(svg|png|jpe?g|webp|ico)$/, // top-level images from public/
  new RegExp(`^(${STATIC_PAGES.join('|')})/index\\.html$`),
  /^assets\/[A-Za-z0-9._-]+\.(js|css|svg|png|jpe?g|webp|woff2?)$/,
  /^share\/[A-Za-z0-9._-]+\.(png|jpe?g|webp)$/,
  /^pick\/[A-Za-z0-9._-]+\/index\.html$/,
  /^api\/(board|snapshots)\.json$/,
  /^api\/agent\/today\.json$/,
  /^api\/archive\/[A-Za-z0-9._-]+\.json$/,
  /^\.github\/(validate-site\.mjs|dependabot\.yml|workflows\/[A-Za-z0-9._-]+\.ya?ml)$/,
];
// Clearer messages for the files this exists to stop.
const FORBIDDEN_NAMES = /(^|\/)(\.env(\..*)?|.*\.(pem|key|p8|p12|sqlite|sqlite-wal|sqlite-shm|db|map|log|bak)|id_rsa.*|\.DS_Store|node_modules|\.npmrc|package(-lock)?\.json)$/i;

const LEAK_PATTERNS = [
  [/\bhf_[A-Za-z0-9]{30,}\b/, 'Hugging Face token'],
  [/\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b/, 'GitHub token'],
  [/\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}\b/, 'API secret key'],
  [/\bAKIA[0-9A-Z]{16}\b/, 'AWS access key'],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, 'Slack token'],
  [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, 'private key'],
  [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, 'JWT'],
  [/\b(?:HF_TOKEN|TYPESAFE_API_KEY)\s*[:=]\s*['"]?[A-Za-z0-9_-]{8,}/, 'provider credential assignment'],
  [/\.ts\.net\b/, 'Tailscale address'],
  [/\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b/, 'private network address'],
  [/(?:127\.0\.0\.1|localhost):\d{2,5}/, 'local server address'],
  [/\/Users\/[A-Za-z0-9._-]+\//, 'local file path'],
];

// Where public data may link. rulesUrl and kalshiUrl are narrower (see src/lib/safeLinks.js).
const RULES_HOSTS = new Set(['assets.kalshi.com', 'kalshi.com']);
const MARKET_HOSTS = new Set(['kalshi.com']);
const DATA_LINK_HOSTS = new Set(['kalshi.com', 'assets.kalshi.com']);
// Hosts the HTML shell may reference (fonts, structured data, footer links).
const HTML_LINK_HOSTS = new Set(['fonts.googleapis.com', 'fonts.gstatic.com', 'bdttalentgroup.com', 'x.com', 'schema.org']);
// Public JSON must never carry these (server/publicJson.js strips them).
const PRIVATE_KEYS = new Set(['lateRun', 'model', 'host', 'usage', 'trackRecord', 'trackRecords', 'worstMiss', 'worstMissPct', 'rating']);

const TEXT_EXT = /\.(html|json|js|mjs|css|svg|txt|xml|md|ya?ml)$|^\.build-commit$|^\.nojekyll$/;

function walk(dir, rel = '') {
  const out = [];
  for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const name = rel ? `${rel}/${entry.name}` : entry.name;
    if (name === '.git') continue;
    if (entry.isSymbolicLink()) out.push({ name, symlink: true });
    else if (entry.isDirectory()) out.push(...walk(dir, name));
    else out.push({ name });
  }
  return out;
}

/** Same rule as src/lib/safeLinks.js: absolute https, no credentials or port, exact host. */
export function safeLink(value, hosts) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  if (value !== value.trim() || /[\s\\<>"'`\u0000-\u001f\u007f]/.test(value)) return false;
  if (!/^https:\/\/[^/]/i.test(value)) return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  return url.protocol === 'https:' && !url.username && !url.password && !url.port && hosts.has(url.hostname);
}

// Text such as "No: 80° or below" is not a URL. A compact scheme payload is, and known network or
// executable schemes remain URL-like even when whitespace is inserted after the colon.
function looksLikeLink(value) {
  const match = String(value).trim().match(/^([a-z][a-z0-9+.-]*):(.*)$/is);
  if (!match) return false;
  if (/^(?:https?|ftp|file|data|javascript|vbscript)$/i.test(match[1])) return true;
  return !/^\s/.test(match[2]);
}

const isObject = (v) => v && typeof v === 'object' && !Array.isArray(v);
const DAY = /^\d{4}-\d{2}-\d{2}$/;

function checkJsonValue(value, where, ctx, errors, key = null) {
  if (Array.isArray(value)) { value.forEach((v, i) => checkJsonValue(v, `${where}[${i}]`, ctx, errors)); return; }
  if (isObject(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (PRIVATE_KEYS.has(k)) errors.push(`${where}.${k}: private field in public data`);
      checkJsonValue(v, `${where}.${k}`, ctx, errors, k);
    }
    return;
  }
  if (typeof value !== 'string') return;
  if (/minimax/i.test(value)) errors.push(`${where}: names the internal model`);
  if (key === 'method' && value !== 'ai' && /m\d|gpt|claude|llama|qwen/i.test(value)) errors.push(`${where}: internal method name "${value}"`);
  if (key === 'rulesUrl') { if (!safeLink(value, RULES_HOSTS)) errors.push(`${where}: unsafe rules link ${JSON.stringify(value.slice(0, 120))}`); return; }
  if (key === 'kalshiUrl' || key === 'url') { if (!safeLink(value, MARKET_HOSTS) && !safeLink(value, ctx.selfHosts)) errors.push(`${where}: unsafe market link ${JSON.stringify(value.slice(0, 120))}`); return; }
  // Other fields may contain prose. Only a value that actually looks like a URI is a link.
  if (!looksLikeLink(value)) return;
  if (!safeLink(value, new Set([...DATA_LINK_HOSTS, ...ctx.selfHosts]))) errors.push(`${where}: unsafe link ${JSON.stringify(value.slice(0, 120))}`);
}

function checkPick(p, where, errors) {
  if (!isObject(p)) return errors.push(`${where}: pick is not an object`);
  if (typeof p.id !== 'string' || !p.id || p.id.length > 200) errors.push(`${where}.id: missing or invalid`);
}

function checkBoard(board, errors) {
  if (!isObject(board)) return errors.push('api/board.json: not an object');
  for (const section of ['sports', 'kalshi']) {
    const s = board[section];
    if (s == null) continue;
    if (!isObject(s)) { errors.push(`api/board.json.${section}: not an object`); continue; }
    if (s.day != null && !DAY.test(String(s.day))) errors.push(`api/board.json.${section}.day: not YYYY-MM-DD`);
    for (const list of ['picks', 'latePicks']) {
      if (s[list] == null) continue;
      if (!Array.isArray(s[list])) { errors.push(`api/board.json.${section}.${list}: not a list`); continue; }
      s[list].forEach((p, i) => checkPick(p, `api/board.json.${section}.${list}[${i}]`, errors));
    }
  }
}

function checkFeed(feed, ctx, errors) {
  const f = 'api/agent/today.json';
  if (!isObject(feed)) return errors.push(`${f}: not an object`);
  if (feed.feed !== 'run-it-bet/agent-feed') errors.push(`${f}.feed: expected "run-it-bet/agent-feed"`);
  if (feed.version !== 1) errors.push(`${f}.version: expected 1`);
  if (feed.day != null && !DAY.test(String(feed.day))) errors.push(`${f}.day: not YYYY-MM-DD`);
  for (const list of ['picks', 'sportsPicks']) if (feed[list] != null && !Array.isArray(feed[list])) errors.push(`${f}.${list}: not a list`);
  if (!isObject(feed.links)) errors.push(`${f}.links: missing`);
  else for (const [k, v] of Object.entries(feed.links)) if (!safeLink(v, ctx.selfHosts)) errors.push(`${f}.links.${k}: must point at ${ctx.origin}`);
  for (const p of [...(feed.picks || []), ...(feed.sportsPicks || [])]) {
    if (p?.detailsUrl != null && !safeLink(p.detailsUrl, ctx.selfHosts)) errors.push(`${f}: detailsUrl must point at ${ctx.origin}`);
  }
}

function checkSnapshots(record, errors) {
  const f = 'api/snapshots.json';
  if (!isObject(record) || !DAY.test(String(record.day)) || !isObject(record.slots)) return errors.push(`${f}: expected { day, slots }`);
  for (const [slot, v] of Object.entries(record.slots)) {
    if (!['08:30', '09:30'].includes(slot)) errors.push(`${f}: unknown slot ${slot}`);
    if (!isObject(v) || Number.isNaN(Date.parse(v.publishedAt))) errors.push(`${f}.${slot}.publishedAt: not a time`);
  }
}

function checkHtml(rel, html, ctx, errors) {
  for (const m of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    const attrs = m[1];
    const src = attrs.match(/\bsrc="([^"]*)"/i)?.[1];
    if (/type="application\/ld\+json"/i.test(attrs)) {
      try { JSON.parse(m[2]); } catch { errors.push(`${rel}: JSON-LD block is not valid JSON`); }
      continue;
    }
    if (!src) { errors.push(`${rel}: inline script (blocked by the CSP; move it into the bundle)`); continue; }
    if (!src.startsWith('/assets/')) errors.push(`${rel}: script from ${src} (only /assets/ is allowed)`);
    else if (!ctx.files.has(src.slice(1).split(/[?#]/)[0])) errors.push(`${rel}: script ${src} is missing`);
  }
  for (const m of html.matchAll(/<link\b[^>]*rel="stylesheet"[^>]*href="([^"]*)"/gi)) {
    const href = m[1];
    if (href.startsWith('/assets/') && !ctx.files.has(href.slice(1).split(/[?#]/)[0])) errors.push(`${rel}: stylesheet ${href} is missing`);
  }
  if (/\son[a-z]+\s*=/i.test(html.replace(/<script\b[\s\S]*?<\/script>/gi, ''))) errors.push(`${rel}: inline event handler attribute`);
  for (const m of html.matchAll(/\b(?:href|src)="([a-z][a-z0-9+.-]*:[^"]*)"/gi)) {
    const link = m[1].replace(/&amp;/g, '&');
    if (/^(mailto|tel):/i.test(link)) continue;
    if (!safeLink(link, new Set([...HTML_LINK_HOSTS, ...ctx.selfHosts]))) errors.push(`${rel}: unsafe link ${JSON.stringify(link.slice(0, 120))}`);
  }
  // Some metadata values are URLs (og:url/image); ordinary title/description text can also contain
  // a colon. Validate only content values that actually look like links.
  for (const m of html.matchAll(/<meta\b[^>]*\bcontent="([^"]*)"[^>]*>/gi)) {
    const link = m[1].replace(/&amp;/g, '&');
    if (looksLikeLink(link) && !safeLink(link, new Set([...HTML_LINK_HOSTS, ...ctx.selfHosts]))) errors.push(`${rel}: unsafe link ${JSON.stringify(link.slice(0, 120))}`);
  }
}

/** Every problem found in `dir`, as human-readable strings. An empty list means it may go live. */
export function validateSite(dir, { origin = DEFAULT_ORIGIN } = {}) {
  const errors = [];
  const originHost = new URL(origin).hostname;
  const ctx = { origin, selfHosts: new Set([originHost]), files: new Set() };
  const entries = walk(dir);
  for (const e of entries) ctx.files.add(e.name);

  for (const { name, symlink } of entries) {
    if (symlink) { errors.push(`${name}: symbolic link`); continue; }
    if (FORBIDDEN_NAMES.test(name)) { errors.push(`${name}: internal or secret-bearing file must not be published`); continue; }
    if (!ALLOWED_PATHS.some((re) => re.test(name))) errors.push(`${name}: not part of the public site layout`);
  }
  for (const name of REQUIRED) if (!ctx.files.has(name)) errors.push(`${name}: missing`);

  for (const { name, symlink } of entries) {
    if (symlink || !TEXT_EXT.test(path.basename(name)) || name.startsWith('.github/')) continue;
    const text = fs.readFileSync(path.join(dir, name), 'utf8');
    for (const [re, what] of LEAK_PATTERNS) if (re.test(text)) errors.push(`${name}: contains a ${what}`);
    if (name.endsWith('.json')) {
      let data;
      try { data = JSON.parse(text); } catch { errors.push(`${name}: not valid JSON`); continue; }
      checkJsonValue(data, name, ctx, errors);
      if (name === 'api/board.json') checkBoard(data, errors);
      else if (name === 'api/agent/today.json') checkFeed(data, ctx, errors);
      else if (name === 'api/snapshots.json') checkSnapshots(data, errors);
      else if (name.startsWith('api/archive/')) checkPick(data, name, errors);
    } else if (name.endsWith('.html')) {
      checkHtml(name, text, ctx, errors);
    }
  }

  if (ctx.files.has('.build-commit')) {
    const stamp = fs.readFileSync(path.join(dir, '.build-commit'), 'utf8').trim();
    // Informational only (which source commit built this, and for which address); never a credential.
    if (!/^[0-9a-f]{40} https:\/\/[A-Za-z0-9.-]+$/.test(stamp)) errors.push('.build-commit: expected "<40-hex commit> <https origin>"');
  }
  return errors;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const i = args.indexOf('--origin');
  const origin = i >= 0 ? args[i + 1] : DEFAULT_ORIGIN;
  const dir = args.find((a, j) => !a.startsWith('--') && args[j - 1] !== '--origin');
  if (!dir) { console.error('usage: validate-site.mjs <site-dir> [--origin https://www.runitbet.com]'); process.exit(2); }
  const errors = validateSite(path.resolve(dir), { origin });
  if (errors.length) {
    console.error(`Site validation FAILED (${errors.length}):`);
    for (const e of errors) console.error(`  - ${e}`);
    process.exit(1);
  }
  console.log(`Site validation passed: ${path.resolve(dir)} (${origin}).`);
}
