# Stand-in narration for the preview video: every teleprompter line, spoken in
# the lab's narrator voice (Kokoro am_michael, as scratchpad voices/voice_all.py).
#   ~/.venvs/tts/bin/python -I tools/narrate.py <lines.json> <out dir>
# lines.json: [{"id": "1-diff", "text": "..."}]. Writes <out>/<sha1(text)[:12]>.wav
# and <out>/index.json {id: {file, dur, text}}. A line whose text did not change
# keeps its clip (cache by text hash).
import sys, re, json, hashlib, os, time
import numpy as np, soundfile as sf
SAY = [(r"\bSCIM\b", "skim"), (r"\bHIPAA\b", "hippa"), (r"\bDC01\b", "D C zero one"), (r"\bAWS\b", "A W S"), (r"\bHR\b", "H R"),
       (r"\bIT\b", "I T"), (r"\bICU\b", "I C U"), (r"\bPIM\b", "P I M"), (r"\bWORM\b", "worm"), (r"\bGitHub\b", "Git Hub"),
       (r"\bServiceNow\b", "Service Now"), (r"\bEntra\b", "Entra")]
def spoken(t):
    for a, b in SAY: t = re.sub(a, b, t)
    return t
lines = json.load(open(sys.argv[1])); out = sys.argv[2]; os.makedirs(out, exist_ok=True)
idx_path = os.path.join(out, "index.json")
index = {}
pipe = None
for l in lines:
    h = hashlib.sha1(("am_michael|" + l["text"]).encode()).hexdigest()[:12]
    wav = os.path.join(out, h + ".wav")
    if not os.path.exists(wav):
        if pipe is None:
            from kokoro import KPipeline
            pipe = KPipeline(lang_code="a", repo_id="hexgrad/Kokoro-82M")
        t0 = time.time()
        audio = np.concatenate([a for _, _, a in pipe(spoken(l["text"]), voice="am_michael", speed=1.0)])
        sf.write(wav, audio, 24000)
        print(l["id"], round(len(audio) / 24000, 2), f"({time.time()-t0:.1f}s)", flush=True)
    info = sf.info(wav)
    index[l["id"]] = {"file": wav, "dur": round(info.frames / info.samplerate, 2), "text": l["text"]}
json.dump(index, open(idx_path, "w"), indent=1)
print("ALL", len(index), "clips,", round(sum(v["dur"] for v in index.values()) / 60, 1), "min", flush=True)
