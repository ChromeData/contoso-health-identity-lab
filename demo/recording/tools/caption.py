#!/usr/bin/env python3
"""Burn captions into silent clips (npm run clips -> npm run captions -- <dir>).

Reads <dir>/watch-lines.json (each step: piece, at, end, text) and every
<dir>/N??-*.mp4, writes <dir>/captioned/<same name>.mp4 with no audio.
One caption style for everything: the script card's look (dark, white
text, amber edge), in a band added under the picture, so a caption never
covers what is on screen (the clip becomes W x (H + BAND)).
"""
import json, os, re, subprocess, sys, tempfile
from PIL import Image, ImageDraw, ImageFont

FONT = '/System/Library/Fonts/HelveticaNeue.ttc'
BG = (15, 15, 15, 220)          # NSColor(white 0.06, alpha 0.86)
AMBER = (255, 189, 77, 255)     # the card's amber
MAXW = 22                       # words per caption chunk
BAND = 198                      # px at 1920 wide: 1920x1242 -> 1920x1440 (4:3)


def chunks(text):
    sents = re.split(r'(?<=[.!?])\s+', text.strip())
    out, cur = [], []
    for s in sents:
        w = s.split()
        if cur and len(cur) + len(w) > MAXW:
            out.append(' '.join(cur)); cur = []
        while len(w) > MAXW:  # one long sentence: split on a comma or in half
            cut = next((i + 1 for i in range(MAXW - 1, 8, -1) if w[i].endswith((',', ';', ':'))), MAXW)
            out.append(' '.join(w[:cut])); w = w[cut:]
        cur += w
    if cur: out.append(' '.join(cur))
    return out


def wrap(draw, text, font, width):
    lines, cur = [], ''
    for word in text.split():
        t = (cur + ' ' + word).strip()
        if draw.textlength(t, font=font) <= width: cur = t
        else: lines.append(cur); cur = word
    if cur: lines.append(cur)
    return lines


def render(text, W, H, path):
    """A W x H transparent canvas; H is the padded height. The caption sits
    centred in the band at the bottom."""
    scale = W / 1920
    band = int(BAND * scale)
    font = ImageFont.truetype(FONT, int(36 * scale), index=0)
    boxw = int(1500 * scale); lh = int(48 * scale)
    img = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    lines = wrap(d, text, font, boxw - int(30 * scale))
    th = len(lines) * lh
    x0 = (W - boxw) // 2; y0 = H - band + (band - th) // 2
    d.rounded_rectangle([x0, y0 + int(4 * scale), x0 + int(5 * scale), y0 + th - int(6 * scale)], radius=int(3 * scale), fill=AMBER)
    for i, ln in enumerate(lines):
        d.text((x0 + int(26 * scale), y0 + i * lh), ln, font=font, fill=(255, 255, 255, 245))
    img.save(path)


def probe(f):
    out = subprocess.check_output(['ffprobe', '-v', 'error', '-select_streams', 'v:0', '-show_entries',
                                   'stream=width,height:format=duration', '-of', 'json', f])
    j = json.loads(out)
    return j['streams'][0]['width'], j['streams'][0]['height'], float(j['format']['duration'])


def main(d):
    lines = json.load(open(os.path.join(d, 'watch-lines.json')))
    outdir = os.path.join(d, 'captioned'); os.makedirs(outdir, exist_ok=True)
    for f in sorted(os.listdir(d)):
        m = re.search(r'N(\d+)(b?)-.*\.mp4$', f)
        if not m: continue
        piece = int(m.group(1)) + (0.5 if m.group(2) else 0)
        steps = [l for l in lines if l.get('piece') == piece and l.get('at') is not None and l.get('text')]
        src = os.path.join(d, f)
        W, H, total = probe(src)
        if not steps: print(f'{f}: no caption lines, skipped'); continue
        tmp = tempfile.mkdtemp(prefix='cap-', dir=outdir)
        cues = []
        for k, s in enumerate(steps):
            a = s['at']
            b = s.get('end') or (steps[k + 1]['at'] if k + 1 < len(steps) else total)
            if k + 1 < len(steps): b = min(b, steps[k + 1]['at'])
            parts = chunks(s['text']); n = sum(len(p.split()) for p in parts) or 1
            t = a
            for p in parts:
                dt = (b - a) * len(p.split()) / n
                cues.append((t, t + dt, p)); t += dt
        band = int(BAND * W / 1920) // 2 * 2
        H2 = H + band
        inputs = ['-i', src]
        chain, last = [f"[0:v]pad={W}:{H2}:0:0:color=0x0f0f0f[pad]"], 'pad'
        for i, (a, b, p) in enumerate(cues):
            png = os.path.join(tmp, f'{i:03d}.png'); render(p, W, H2, png)
            inputs += ['-i', png]
            chain.append(f"[{last}][{i + 1}:v]overlay=0:0:enable='between(t,{a:.2f},{b:.2f})'[v{i}]")
            last = f'v{i}'
        out = os.path.join(outdir, f)
        script = os.path.join(tmp, 'graph.txt'); open(script, 'w').write(';'.join(chain))
        subprocess.check_call(['ffmpeg', '-v', 'error', '-y', *inputs, '-filter_complex_script', script, '-map', f'[{last}]',
                               '-an', '-c:v', 'libx264', '-crf', '20', '-preset', 'veryfast', '-pix_fmt', 'yuv420p', out])
        print(f'{f}: {len(cues)} captions -> {out}')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
