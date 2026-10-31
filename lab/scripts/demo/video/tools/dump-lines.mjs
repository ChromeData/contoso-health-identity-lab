import { scenes } from '/Users/michaelwilliams/contoso-health-identity-lab/lab/scripts/demo/video/scenes.mjs';
const out = [];
for (const s of scenes()) {
  if (s.kind === 'clip') out.push({ scene: s.id, beat: 0, text: "Hello, I'm Michael. I have ten-plus years in IT, identity and privileged access. In this lab I built a hospital identity platform, mostly from code, where every change is reviewed and every result is measured.", voice: 'you' });
  s.beats.forEach((b, i) => { if (b.say) out.push({ scene: s.id, beat: i, text: b.say, voice: b.audio ? 'you' : 'narrator' }); });
}
console.log(JSON.stringify(out));
