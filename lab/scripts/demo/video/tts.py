#!/usr/bin/env python3
"""tts.py <out.mp3> <voice> <text-file> - narration via the lab's Azure OpenAI gpt-4o-mini-tts (Entra token, no keys)."""
import json, ssl, subprocess, sys, urllib.request, urllib.error
out, voice, src = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src, encoding='utf-8').read().strip()
ep = subprocess.run(['az','cognitiveservices','account','show','-n','oai-idlab-20f1','-g','rg-identity-lab-ai','--query','properties.endpoint','-o','tsv'],capture_output=True,text=True).stdout.strip().rstrip('/')
tok = subprocess.run(['az','account','get-access-token','--resource','https://cognitiveservices.azure.com','--query','accessToken','-o','tsv'],capture_output=True,text=True).stdout.strip()
ctx = ssl.create_default_context()
if not ctx.get_ca_certs(): ctx.load_verify_locations('/etc/ssl/cert.pem')
body = {"model":"gpt-4o-mini-tts","voice":voice,"input":text,"response_format":"mp3",
        "instructions":"Calm, confident senior identity engineer presenting a live lab. Clear diction, natural pace, slight warmth, no hype."}
req = urllib.request.Request(f"{ep}/openai/deployments/narration-tts/audio/speech?api-version=2025-03-01-preview",
        data=json.dumps(body).encode(), headers={"Authorization":f"Bearer {tok}","Content-Type":"application/json"}, method="POST")
for attempt in range(6):
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=180) as r:
            open(out,'wb').write(r.read()); print('ok', out); break
    except urllib.error.HTTPError as e:
        msg = e.read().decode()[:300]
        if e.code in (404, 429, 500, 503) and attempt < 5:
            import time; time.sleep(30); continue
        sys.exit(f"HTTP {e.code}: {msg}")
