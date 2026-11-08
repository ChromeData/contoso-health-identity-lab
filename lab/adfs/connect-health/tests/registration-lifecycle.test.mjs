// node --test lab/adfs/connect-health/tests/registration-lifecycle.test.mjs
// Static check of envs/dev/connect_health_registration.tf (ADR 0031) that
// terraform test cannot make: a mocked plan has no drift, so it cannot show
// what a later apply does to an account that register.sh close disabled.
// What is held: the azuread_user ignores account_enabled, so an unrelated
// apply in the window cannot switch the closed account back on; and close
// really writes accountEnabled false (the drift the line is there for).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../../../..');
const tf = fs.readFileSync(path.join(repo, 'lab/terraform/envs/dev/connect_health_registration.tf'), 'utf8');
const sh = fs.readFileSync(path.join(repo, 'lab/adfs/connect-health/register.sh'), 'utf8');

// The body of one top-level resource block (braces counted; no HCL parser
// needed for this file, which has no braces inside strings).
function resourceBody(src, type, name) {
  const head = `resource "${type}" "${name}" {`;
  const start = src.indexOf(head);
  assert.notEqual(start, -1, `${type}.${name} not found`);
  let depth = 0;
  for (let i = start + head.length - 1; i < src.length; i++) {
    if (src[i] === '{') depth++;
    if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`${type}.${name}: unbalanced braces`);
}
// Comments out, so a commented-out line does not count.
const code = (s) => s.split('\n').map((l) => l.replace(/#.*$/, '')).join('\n');

test('the registration user ignores account_enabled (a later apply cannot undo register.sh close)', () => {
  const body = code(resourceBody(tf, 'azuread_user', 'connect_health_registration'));
  const m = body.match(/lifecycle\s*{[\s\S]*?ignore_changes\s*=\s*\[([^\]]*)\]/);
  assert.ok(m, 'no lifecycle ignore_changes on azuread_user.connect_health_registration');
  assert.ok(m[1].split(',').map((s) => s.trim()).includes('account_enabled'), `ignore_changes is [${m[1]}]`);
});

test('the user is still created enabled, and the time box is still there', () => {
  const body = code(resourceBody(tf, 'azuread_user', 'connect_health_registration'));
  assert.match(body, /account_enabled\s*=\s*true/);
  assert.match(body, /timecmp\(plantimestamp\(\), var\.connect_health_registration_until_utc\) < 0/);
});

test('register.sh close disables the account and reads it back', () => {
  assert.match(sh, /"accountEnabled": false/);
  assert.match(sh, /\[ "\$en" = false \]/);
});
