#!/usr/bin/env python3
"""Count how many times a secret value appears in Terraform's files.

WHY a separate script: the whole finding rests on this count, so it is the
one piece with its own tests (tests/test_count_secret.py). It reads the value
from the environment variable STATE_LEAK_SECRET, never from argv (argv is
visible in `ps`), and never prints it: only counts and the value's length.

It looks for the value as written and as JSON escapes it, and it opens saved
plan files (zip archives) and counts inside every member, because a plan file
is where Terraform also keeps data source results.

Usage:  STATE_LEAK_SECRET=... python3 -I count_secret.py FILE [FILE ...]
        python3 -I count_secret.py --verdict <8 counts>   (run.sh's verdict; exit 0/1/2)
Prints one line per file: "<count>\t<path>". A path that does not exist
prints "absent". Exit 0 when it ran; exit 2 when it could not (no value set,
or a file it could not read), so a broken scan never reads as zero.
"""

import json
import os
import sys
import zipfile


def forms(secret):
    """The byte strings the value can appear as in Terraform's JSON files."""
    raw = secret.encode()
    escaped = json.dumps(secret)[1:-1].encode()
    return {raw, escaped}


def count_in_bytes(data, secret):
    """Occurrences of any form of the value in one blob.

    Forms are de-duplicated (a plain alphanumeric value has one form), so
    a single occurrence is never counted twice.
    """
    return sum(data.count(f) for f in forms(secret))


def count_in_file(path, secret):
    """Occurrences in a file; for a zip (a saved plan), across all members."""
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as zf:
            return sum(count_in_bytes(zf.read(n), secret) for n in zf.namelist())
    with open(path, "rb") as fh:
        return count_in_bytes(fh.read(), secret)


FILES = ("state", "backup", "plan", "log")


def verdict(datasource, ephemeral):
    """Problems with a run's counts, as a list of plain sentences ([] = as stated).

    Each argument maps FILES to a count string ("0", "2", "absent").
    What the README states, all of which must hold:
      * the data source path put the value in terraform.tfstate, its backup
        AND the saved plan (each >= 1; "absent" is a failure: the run was
        built to write a backup and a plan);
      * the ephemeral path wrote a state file and a backup and a plan, and the
        value is in none of them (each exactly 0);
      * neither path printed the value (output 0).
    """
    problems = []
    for f in ("state", "backup", "plan"):
        v = datasource.get(f, "absent")
        if not (v.isdigit() and int(v) >= 1):
            problems.append(f"data source path: the value is not in its {f} file (got {v})")
        e = ephemeral.get(f, "absent")
        if e != "0":
            problems.append(f"ephemeral path: {f} file should hold the value 0 times (got {e})")
    for name, counts in (("data source", datasource), ("ephemeral", ephemeral)):
        if counts.get("log", "absent") != "0":
            problems.append(f"{name} path: Terraform output should hold the value 0 times (got {counts.get('log')})")
    return problems


def main_verdict(args):
    if len(args) != 8:
        print("usage: count_secret.py --verdict DS_STATE DS_BACKUP DS_PLAN DS_LOG EP_STATE EP_BACKUP EP_PLAN EP_LOG",
              file=sys.stderr)
        return 2
    problems = verdict(dict(zip(FILES, args[:4])), dict(zip(FILES, args[4:])))
    for p in problems:
        print(f"UNEXPECTED: {p}")
    if problems:
        return 1
    print("AS STATED: the data source wrote the secret into state, its backup and the saved plan in")
    print("plaintext; the ephemeral resource read it (precondition passed) and left it in no state,")
    print("backup, plan or output file.")
    return 0


def main(argv):
    if argv[:1] == ["--verdict"]:
        return main_verdict(argv[1:])
    secret = os.environ.get("STATE_LEAK_SECRET", "")
    if len(secret) < 16:
        print("error: STATE_LEAK_SECRET is unset or shorter than 16 characters", file=sys.stderr)
        return 2
    if not argv:
        print("usage: count_secret.py FILE [FILE ...]", file=sys.stderr)
        return 2
    for path in argv:
        if not os.path.exists(path):
            print(f"absent\t{path}")
            continue
        try:
            n = count_in_file(path, secret)
        except (OSError, zipfile.BadZipFile) as exc:
            print(f"error: cannot read {path}: {exc}", file=sys.stderr)
            return 2
        print(f"{n}\t{path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
