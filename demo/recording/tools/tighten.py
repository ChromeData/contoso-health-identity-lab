#!/usr/bin/env python3
"""Tighten a narrated preview: every silent stretch longer than MAX seconds is
cut down to MAX (half kept at each end), picture and sound together. The
recorded screens are not changed, only the dead time between lines.

  python3 -I tools/tighten.py IN.narrated.mp4 [OUT.mp4] [--max 1.6] [--keep-before 16]

Without OUT the input is replaced; the untouched file is kept next to it as
*.untightened.mp4. Re-encodes (libx264 crf 20, aac 160k). Prints the gaps it cut.
"""
import os, re, subprocess, sys

FF = '/opt/homebrew/bin/ffmpeg' if os.path.exists('/opt/homebrew/bin/ffmpeg') else 'ffmpeg'
FP = '/opt/homebrew/bin/ffprobe' if os.path.exists('/opt/homebrew/bin/ffprobe') else 'ffprobe'

def main():
    args = [a for a in sys.argv[1:]]
    mx = 1.6; skip = 0.0
    if '--keep-before' in args:   # e.g. N00's opening: the owner's own words, held on purpose
        i = args.index('--keep-before'); skip = float(args[i + 1]); del args[i:i + 2]
    if '--max' in args:
        i = args.index('--max'); mx = float(args[i + 1]); del args[i:i + 2]
    src = args[0]; out = args[1] if len(args) > 1 else None
    dur = float(subprocess.check_output([FP, '-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', src]).decode())
    log = subprocess.run([FF, '-i', src, '-af', f'silencedetect=noise=-40dB:d={mx}', '-f', 'null', '-'], capture_output=True, text=True).stderr
    starts = [float(x) for x in re.findall(r'silence_start: ([\d.]+)', log)]
    ends = [float(x) for x in re.findall(r'silence_end: ([\d.]+)', log)]
    if len(ends) < len(starts): ends.append(dur)
    cuts = []
    for s, e in zip(starts, ends):
        if e - s > mx and s >= skip:
            cuts.append((s + mx / 2, e - mx / 2))
    if not cuts:
        print(f'{os.path.basename(src)}: nothing over {mx} s'); return
    keep, t = [], 0.0
    for a, b in cuts:
        if a > t: keep.append((t, a))
        t = b
    if t < dur: keep.append((t, dur))
    sel = '+'.join(f'between(t,{a:.3f},{b:.3f})' for a, b in keep)
    tmp = (out or src) + '.tmp.mp4'
    subprocess.run([FF, '-v', 'error', '-y', '-i', src, '-vf', f"select='{sel}',setpts=N/FRAME_RATE/TB", '-af', f"aselect='{sel}',asetpts=N/SR/TB",
                    '-c:v', 'libx264', '-preset', 'veryfast', '-crf', '20', '-pix_fmt', 'yuv420p', '-c:a', 'aac', '-b:a', '160k', '-movflags', '+faststart', tmp], check=True)
    if out: os.replace(tmp, out)
    else:
        os.replace(src, src.replace('.narrated.mp4', '.untightened.mp4') if src.endswith('.narrated.mp4') else src + '.untightened.mp4')
        os.replace(tmp, src)
    new = float(subprocess.check_output([FP, '-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', out or src]).decode())
    print(f'{os.path.basename(src)}: {len(cuts)} gaps cut to {mx} s, {dur:.1f} s -> {new:.1f} s')

if __name__ == '__main__':
    main()
