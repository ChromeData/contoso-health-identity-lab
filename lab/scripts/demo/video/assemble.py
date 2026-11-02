#!/usr/bin/env python3
"""assemble.py - build the demo video from the recorded scenes.

For each scene: cut every narration beat's window out of the raw recording
(loading screens between beats are dropped), lay the beat's narration on it,
and join the beats. Then crossfade the scenes, normalise loudness, and add a
subtitle track built from the narration text.

  python3 assemble.py [--intro intro.mp4] [--out name.mp4] [--only 01,02]
"""
import json, os, re, subprocess, sys, glob

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '../../../..'))
OUT = os.path.join(REPO, 'lab/evidence/out/video')
FF = '/opt/homebrew/bin/ffmpeg' if os.path.exists('/opt/homebrew/bin/ffmpeg') else 'ffmpeg'
FP = FF.replace('ffmpeg', 'ffprobe')
XF = 0.5          # crossfade between scenes (s)
LEAD = 0.5        # narration delay at the start of a scene
GAP = 0.15        # narration delay inside a scene
TAIL = 0.3        # breath after a line before the next beat (the recorder holds 0.35 s)
FIT_MAX = 1.5     # fastest a beat's footage may play to close a gap after a shorter line
args = sys.argv[1:]
intro = args[args.index('--intro') + 1] if '--intro' in args else None
name = args[args.index('--out') + 1] if '--out' in args else 'contoso-health-lab-demo.mp4'

def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode: sys.exit('ffmpeg failed:\n' + r.stderr[-3000:])
    return r

def dur(f):
    return float(subprocess.run([FP, '-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', f], capture_output=True, text=True).stdout)

index = json.load(open(os.path.join(OUT, 'audio/index.json')))
tls = sorted(glob.glob(os.path.join(OUT, 'raw/*.timeline.json')))
tls = [t for t in tls if os.path.basename(t)[:2].isdigit()]
if '--only' in args:   # preview a subset, e.g. --only 01,02,05
    keep = args[args.index('--only') + 1].split(',')   # scenes play in the order listed
    tls = [t for k in keep for t in tls if os.path.basename(t)[:2] == k]
os.makedirs(os.path.join(OUT, 'scenes'), exist_ok=True)

scene_files, subs = [], []   # subs: (scene_idx, local_start, local_end, text)
for si, tlf in enumerate(tls):
    tl = json.load(open(tlf)); sid = tl['id']; beats = tl['beats']
    if tl.get('clip'):   # external clip with its own audio: conform to 1080p30 and keep it whole
        out = os.path.join(OUT, 'scenes', f'{sid}.mp4')
        run([FF, '-y', '-v', 'error', '-i', tl['clip'], '-vf', 'fps=30,scale=1920:1080:force_original_aspect_ratio=decrease:flags=lanczos,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,setsar=1,format=yuv420p',
             '-c:v', 'libx264', '-preset', 'medium', '-crf', '17', '-c:a', 'aac', '-b:a', '192k', '-ar', '48000', '-ac', '2', out])
        scene_files.append(out); print(f'scene {sid}: clip {dur(out):.1f}s'); continue
    aud = index[sid]
    if len(beats) != len(aud):
        sys.exit(f'{sid}: recorded {len(beats)} beats but narration has {len(aud)} (re-record it)')
    cmd = [FF, '-y', '-v', 'error', '-i', tl['raw']]
    for a in aud: cmd += ['-i', a['file']]
    fc, cat, t = [], '', 0.0
    for i, b in enumerate(beats):
        s, e = max(0.0, b['vStart']), b['vEnd']; L = e - s
        delay = LEAD if i == 0 else GAP
        # Fit the footage to the narration when they were recorded apart (a re-voiced line over an older
        # portal recording): a long line holds the last frame, a short one plays the footage faster.
        need = delay + aud[i]['dur'] + TAIL
        speed = min(FIT_MAX, L / (need + 0.6)) if L > need + 1.0 else 1.0
        hold = max(0.0, need - L / speed)
        fit = (f",setpts=PTS/{speed:.4f}" if speed > 1 else '') + (f",tpad=stop_mode=clone:stop_duration={hold:.3f}" if hold > 0.05 else '')
        L = L / speed + (hold if hold > 0.05 else 0)
        fc.append(f"[0:v]trim=start={s:.3f}:end={e:.3f},setpts=PTS-STARTPTS{fit},fps=30,scale=1920:1080:flags=lanczos,setsar=1,format=yuv420p[v{i}]")
        fc.append(f"[{i+1}:a]aresample=48000,aformat=channel_layouts=stereo,adelay={int(delay*1000)}:all=1,apad,atrim=0:{L:.3f},asetpts=PTS-STARTPTS[a{i}]")
        cat += f'[v{i}][a{i}]'
        # subtitles: split the beat's text into short chunks, timed by length
        text = aud[i]['say']
        parts = []
        for sent in re.split(r'(?<=[.!?:])\s+', text):
            while len(sent) > 84:
                cut = sent.rfind(', ', 0, 84); cut = cut + 1 if cut > 30 else sent.rfind(' ', 0, 84)
                parts.append(sent[:cut].strip()); sent = sent[cut:].strip()
            if sent: parts.append(sent)
        total = sum(len(p) for p in parts); a0 = t + delay; D = aud[i]['dur']
        for p in parts:
            d = D * len(p) / total; subs.append((si, a0, a0 + d, p)); a0 += d
        t += L
    fc.append(f"{cat}concat=n={len(beats)}:v=1:a=1[v][a]")
    out = os.path.join(OUT, 'scenes', f'{sid}.mp4')
    run(cmd + ['-filter_complex', ';'.join(fc), '-map', '[v]', '-map', '[a]', '-c:v', 'libx264', '-preset', 'medium', '-crf', '17',
               '-c:a', 'aac', '-b:a', '192k', '-ar', '48000', out])
    scene_files.append(out); print(f'scene {sid}: {t:.1f}s')

if intro: scene_files.insert(0, intro); subs = [(si + 1, a, b, p) for si, a, b, p in subs]
lens = [dur(f) for f in scene_files]
starts = [sum(lens[:k]) - k * XF for k in range(len(lens))]
total = sum(lens) - XF * (len(lens) - 1)

# SRT
def ts(x):
    h, r = divmod(x, 3600); m, s = divmod(r, 60); return f"{int(h):02}:{int(m):02}:{int(s):02},{int(round((s % 1) * 1000)):03}"
srt = os.path.join(OUT, name.replace('.mp4', '.srt'))
with open(srt, 'w') as f:
    for n, (si, a, b, p) in enumerate(subs, 1):
        f.write(f"{n}\n{ts(starts[si] + a)} --> {ts(starts[si] + b - 0.05)}\n{p}\n\n")

# crossfade chain
cmd = [FF, '-y', '-v', 'error']
for f in scene_files: cmd += ['-i', f]
cmd += ['-i', srt]
fc, vl, al = [], '[0:v]', '[0:a]'
for k in range(1, len(scene_files)):
    off = starts[k]
    fc.append(f"{vl}[{k}:v]xfade=transition=fade:duration={XF}:offset={off:.3f}[vx{k}]"); vl = f'[vx{k}]'
    fc.append(f"{al}[{k}:a]acrossfade=d={XF}:c1=tri:c2=tri[ax{k}]"); al = f'[ax{k}]'
fc.append(f"{vl}fade=t=in:st=0:d=0.6,fade=t=out:st={total-1.0:.3f}:d=1.0[vout]")
fc.append(f"{al}loudnorm=I=-16:TP=-1.5:LRA=11,afade=t=out:st={total-1.0:.3f}:d=1.0[aout]")
final = os.path.join(OUT, name)
run(cmd + ['-filter_complex', ';'.join(fc), '-map', '[vout]', '-map', '[aout]', '-map', f'{len(scene_files)}:s',
           '-c:v', 'libx264', '-preset', 'slow', '-crf', '18', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-b:a', '192k', '-ar', '48000',
           '-c:s', 'mov_text', '-metadata:s:s:0', 'language=eng', '-metadata', 'title=Contoso Health identity lab - live tour',
           '-movflags', '+faststart', final])
print(f'{final}  {total/60:.1f} min, {len(scene_files)} scenes; subtitles {srt}')
