// =============================================================================
// schedule.mjs - run the sync again only after the previous one has ended.
// -----------------------------------------------------------------------------
// WHY not setInterval: it starts a new cycle on the clock, even while the
// last one is still waiting on OrangeHRM or GitHub. Two cycles at once can
// interleave: an older cycle holding stale HR rows could read the feed AFTER
// a newer cycle wrote a termination, and write that worker back to active
// (its write would carry the newer feed's version, so the sha check passes).
// Here the next cycle is scheduled only when the current one has finished,
// so one cycle reads and writes at a time. A slow cycle delays the next
// one; it never overlaps it.
// =============================================================================
export function runSerially(fn, everyMs, { setTimer = setTimeout } = {}) {
  let stopped = false;
  let timer;
  const loop = async () => {
    try { await fn(); } catch { /* fn reports its own errors */ }
    if (!stopped) timer = setTimer(loop, everyMs);
  };
  const first = loop();
  return { first, stop() { stopped = true; clearTimeout(timer); } };
}
