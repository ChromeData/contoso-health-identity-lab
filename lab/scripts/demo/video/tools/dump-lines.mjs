import { pathToFileURL } from 'node:url';
// Resolve scenes.mjs relative to this tool (it sits in tools/, scenes.mjs one dir up) so
// the checkout can live anywhere; an optional first argument overrides the path.
const scenesUrl = process.argv[2] ? pathToFileURL(process.argv[2]).href : new URL('../scenes.mjs', import.meta.url).href;
const { scenes } = await import(scenesUrl);
const out = [];
for (const s of scenes()) {
  if (s.kind === 'clip') out.push({ scene: s.id, beat: 0, text: "Hi, I'm Michael. I've spent ten-plus years in IT, identity and privileged access. This lab is a hospital's badge system that I built: who gets in, to what, and when it stops. Every change reviewed, every result measured.", voice: 'you' });
  s.beats.forEach((b, i) => { if (b.say) out.push({ scene: s.id, beat: i, text: b.say, voice: b.audio ? 'you' : 'narrator' }); });
}
console.log(JSON.stringify(out));
