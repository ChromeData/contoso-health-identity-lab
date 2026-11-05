// Child process for tests/lib.test.mjs: one freshTotp call, real waits, a
// clock offset so the run starts 10 s into a 30-s window. Prints the code.
const lib = await import('../lib.mjs');
const offset = Number(process.env.T0) - Number(process.env.START);
const clock = { now: () => Date.now() + offset, sleep: (ms) => new Promise((r) => setTimeout(r, ms)) };
process.stdout.write(await lib.freshTotp(process.env.UPN, process.env.SEED, clock));
