import { pathToFileURL } from 'node:url';
// Resolve scenes.mjs relative to this tool (it sits in tools/, scenes.mjs one dir up) so
// the checkout can live anywhere; an optional first argument overrides the path.
const scenesUrl = process.argv[2] ? pathToFileURL(process.argv[2]).href : new URL('../scenes.mjs', import.meta.url).href;
const { scenes } = await import(scenesUrl);
const out = [];
for (const s of scenes()) {
  if (s.kind === 'clip') out.push({ scene: s.id, beat: 0, text: "Hello, I'm Michael. I have ten-plus years in IT, identity and privileged access. In this lab I built a hospital identity platform, mostly from code, where every change is reviewed and every result is measured.", voice: 'you' });
  s.beats.forEach((b, i) => { if (b.say) out.push({ scene: s.id, beat: i, text: b.say, voice: b.audio ? 'you' : 'narrator' }); });
}
console.log(JSON.stringify(out));
