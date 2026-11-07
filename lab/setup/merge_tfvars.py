#!/usr/bin/env python3
"""Merge a freshly generated terraform.tfvars with the one already on disk.

after-signup.sh step B rewrites envs/bootstrap/terraform.tfvars. A re-run must
not drop settings an admin added later (apply_azure_scope, the VM operator
role, the delete-lock map, the pipeline config vault's custom name, the
EVIDENCE / HR-SYNC switches ...): the next apply would quietly undo them.

    python3 -I merge_tfvars.py OLD NEW [--keep-old KEY ...] [--refuse-change KEY ...] > MERGED

Rules (one top-level assignment = one key, multi-line lists/maps included):
  * a key in NEW wins, unless it is named with --keep-old and OLD has it;
  * a key only in OLD is copied verbatim (with the comment lines just above it);
  * NEW's order first, then OLD-only keys in their old order;
  * --refuse-change KEY: if both files set KEY to different values, stop
    (exit 3, nothing written). Used for pipeline_config_vault_name: a new
    name would make the next apply REPLACE the vault.
Stdlib only; values are copied as text, never printed elsewhere.
"""
import re
import sys

KEY = re.compile(r'^([A-Za-z_][A-Za-z0-9_-]*)\s*=')


def depth_change(line):
    """Bracket depth change of one line, ignoring strings and # comments."""
    d, in_str, esc = 0, False, False
    for ch in line:
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '#':
            break
        elif ch in '[{(':
            d += 1
        elif ch in ']})':
            d -= 1
    return d


def parse(text):
    """Return [(key, block_text)] in file order; blocks keep their comments."""
    out, pending, cur, depth = [], [], None, 0
    for line in text.splitlines(keepends=True):
        if cur is None:
            m = KEY.match(line)
            if m:
                cur = [m.group(1), pending + [line]]
                pending = []
                depth = depth_change(line)
                if depth <= 0:
                    out.append((cur[0], ''.join(cur[1])))
                    cur = None
            elif line.lstrip().startswith(('#', '//')):
                pending.append(line)
            elif not line.strip():
                pending = []
        else:
            cur[1].append(line)
            depth += depth_change(line)
            if depth <= 0:
                out.append((cur[0], ''.join(cur[1])))
                cur, depth = None, 0
    if cur is not None:
        raise ValueError(f'unclosed value for {cur[0]}')
    return out


class Refused(Exception):
    pass


def strip_comment(line):
    """The line without a trailing # or // comment (a # inside a string stays)."""
    in_str, esc = False, False
    for i, ch in enumerate(line):
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == '#' or line.startswith('//', i):
            return line[:i]
    return line


def value_of(block):
    """The assignment's value text, comments and whitespace removed."""
    body = ''.join(strip_comment(l) for l in block.splitlines(keepends=True))
    return re.sub(r'\s+', '', body.split('=', 1)[1])


# An old value that names nothing yet (the example file ships "") may be
# filled in: there is no live resource to replace.
UNSET = ('""', 'null', '')


def merge(old_text, new_text, keep_old=(), refuse_change=()):
    old, new = parse(old_text), parse(new_text)
    old_map = dict(old)
    for k, block in new:
        if k in refuse_change and k in old_map and value_of(old_map[k]) not in UNSET and value_of(old_map[k]) != value_of(block):
            raise Refused(f'{k} differs from the existing terraform.tfvars: changing it would replace a live resource. Change the file by hand on purpose, or unset the override.')
    new_keys = [k for k, _ in new]
    parts = []
    for k, block in new:
        parts.append(old_map[k] if (k in keep_old and k in old_map) else block)
    extra = [(k, b) for k, b in old if k not in new_keys]
    if extra:
        parts.append('\n# ---- kept from the previous terraform.tfvars (set after setup) ----\n')
        parts.extend(b for _, b in extra)
    return ''.join(p if p.endswith('\n') else p + '\n' for p in parts)


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    keep, refuse = [], []
    rest = argv[3:]
    while rest:
        if rest[0] not in ('--keep-old', '--refuse-change') or len(rest) < 2:
            print('usage: merge_tfvars.py OLD NEW [--keep-old KEY ...] [--refuse-change KEY ...]', file=sys.stderr)
            return 2
        (keep if rest[0] == '--keep-old' else refuse).append(rest[1])
        rest = rest[2:]
    try:
        old_text = open(argv[1]).read()
    except FileNotFoundError:
        old_text = ''
    try:
        merged = merge(old_text, open(argv[2]).read(), keep, refuse)
    except Refused as e:
        print(f'refused: {e}', file=sys.stderr)
        return 3
    sys.stdout.write(merged)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
