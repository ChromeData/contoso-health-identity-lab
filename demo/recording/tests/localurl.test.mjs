// Local screens are shown through the cockpit's server, never as a
// /Users/... path (lib/localurl.mjs).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setLocalBase, localUrl, resolveLocal, CARD_FILE } from '../lib/localurl.mjs';

const DEMO = path.join(os.homedir(), 'contoso-demo');
setLocalBase('http://localhost:4747');

test('a card is /card with its hash', () => {
  assert.equal(localUrl(`file://${CARD_FILE}#abc_-1`), 'http://localhost:4747/card#abc_-1');
  assert.equal(resolveLocal('/card').file, CARD_FILE);
});

test('a captured screen is /shots/... and resolves back to its file', () => {
  const dir = fs.mkdtempSync(path.join(DEMO, 'captures', 'zz-localurl-test-'));
  try {
    const f = path.join(dir, 'a shot.png');
    fs.writeFileSync(f, 'x');
    fs.writeFileSync(path.join(dir, '.secret.png'), 'x');
    const u = localUrl(`file://${f}`);
    assert.match(u, /^http:\/\/localhost:4747\/shots\/zz-localurl-test-[^/]+\/a%20shot\.png$/);
    assert.ok(!u.includes('/Users/'));
    const p = new URL(u).pathname;
    assert.equal(resolveLocal(p).file, fs.realpathSync(f));
    assert.equal(resolveLocal(p.replace('a%20shot.png', '.secret.png')), null);
    assert.equal(resolveLocal(p.replace('a%20shot.png', '..%2F..%2Fcockpit%2F.state%2Fui-key')), null);
    assert.equal(resolveLocal('/shots/nothing/registered.png'), null);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('files in hidden folders or outside ~/contoso-demo stay as they are (and are refused by web.show)', () => {
  assert.equal(localUrl('file:///etc/hosts'), 'file:///etc/hosts');
  const hid = `file://${path.join(DEMO, 'cockpit', '.state', 'ui-key.png')}`;
  assert.equal(localUrl(hid), hid);
  assert.equal(localUrl('https://github.com/x'), 'https://github.com/x');
});
