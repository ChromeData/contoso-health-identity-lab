// Local screens on camera without a /Users/... path (2026-11-11 clips: the
// captured screens of web.show and the drawn cards of ui/card.html opened as
// file://, and the address bar showed the home folder path in N04, N04b,
// N11, N14). Like the maps (http://localhost:<port>/map, commit c33970d), they
// are served by the cockpit's own server, to this Mac only, with no key:
//   ui/card.html#<spec>                    -> http://localhost:<port>/card#<spec>
//   ~/contoso-demo/captures/<f>            -> http://localhost:<port>/shots/<f>
//   ~/contoso-demo/cockpit/.v2/<k>/<f>     -> http://localhost:<port>/shots/<k>/<f>
//   ~/contoso-demo/cockpit/.lab-main/<f>   -> http://localhost:<port>/shots/main/<f>
// steps.mjs keeps its file:// addresses (the checks read the files from them);
// Browser.open turns them into these on the way out. Only the folders of files
// handed out this way are served (registered here), never a hidden folder.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DEMO = path.join(os.homedir(), 'contoso-demo');
const PREFIXES = [
  [path.join(DEMO, 'captures') + '/', ''],
  [path.join(DEMO, 'cockpit', '.v2') + '/', ''],
  [path.join(DEMO, 'cockpit', '.lab-main') + '/', 'main/'],
  [DEMO + '/', ''],
];
export const CARD_FILE = new URL('../ui/card.html', import.meta.url).pathname;
const TYPES = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.webp': 'image/webp',
  '.webm': 'video/webm', '.mp4': 'video/mp4', '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json', '.txt': 'text/plain; charset=utf-8', '.woff2': 'font/woff2' };

let BASE = null;
const dirs = new Map();   // '/shots/a/b/' -> absolute folder
export function setLocalBase(b) { BASE = b ? b.replace(/\/$/, '') : null; }
export const localBase = () => BASE;
const enc = (rel) => rel.split('/').map(encodeURIComponent).join('/');

// A file:// address as the served one (unchanged when it can't be served).
export function localUrl(u) {
  if (!BASE || typeof u !== 'string' || !u.startsWith('file://')) return u;
  const m = /^file:\/\/([^?#]*)([?#].*)?$/.exec(u); if (!m) return u;
  const f = decodeURIComponent(m[1]), tail = m[2] || '';
  if (f === CARD_FILE) return `${BASE}/card${tail}`;
  const pre = PREFIXES.find(([p]) => f.startsWith(p)); if (!pre) return u;
  const rel = pre[1] + f.slice(pre[0].length);
  const dir = path.posix.dirname(rel);
  if (dir === '.' || rel.split('/').some((x) => !x || x.startsWith('.'))) return u;
  dirs.set(`/shots/${enc(dir)}/`, path.dirname(f));
  return `${BASE}/shots/${enc(rel)}${tail}`;
}

// The server's side: a /shots/... or /card path -> { file, type } or null.
export function resolveLocal(pathname) {
  if (pathname === '/card' || pathname === '/card/') return { file: CARD_FILE, type: TYPES['.html'] };
  if (!pathname.startsWith('/shots/')) return null;
  let best = null;
  for (const [k, d] of dirs) if (pathname.startsWith(k) && (!best || k.length > best[0].length)) best = [k, d];
  if (!best) return null;
  let rest;
  try { rest = decodeURIComponent(pathname.slice(best[0].length)); } catch { return null; }
  if (!rest || rest.split('/').some((x) => !x || x === '..' || x.startsWith('.'))) return null;
  const type = TYPES[path.extname(rest).toLowerCase()]; if (!type) return null;
  try {
    const root = fs.realpathSync(best[1]);
    const file = fs.realpathSync(path.join(best[1], rest));
    if (!file.startsWith(root + path.sep) || !fs.statSync(file).isFile()) return null;
    return { file, type };
  } catch { return null; }
}
