#!/usr/bin/env python3
"""Diagnóstico (ENSAIO): como o GHCR guarda o atestado? Usa só o GITHUB_TOKEN do job. Imprime status e corpos de resposta (nenhum segredo)."""
import base64, json, os, sys, urllib.request, urllib.error
E = os.environ
dono = E["GITHUB_REPOSITORY_OWNER"].lower()
tok = E["GITHUB_TOKEN"]
def req(url, hdr=None):
    r = urllib.request.Request(url, headers=hdr or {})
    try:
        with urllib.request.urlopen(r, timeout=30) as f:
            return f.status, dict(f.headers), f.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()
for nome, dg in (("ensaio-release", E["PONTEIRO_DIGEST"]), ("ensaio-api", E["API_DIGEST"])):
    repo = f"{dono}/{nome}"
    b = base64.b64encode(f"x:{tok}".encode()).decode()
    s, h, c = req(f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull", {"Authorization": "Basic " + b})
    bearer = json.loads(c)["token"] if s == 200 else ""
    A = {"Authorization": "Bearer " + bearer, "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json"}
    print("=====", repo, dg, "token", s)
    for rotulo, url in (("referrers(sem filtro)", f"https://ghcr.io/v2/{repo}/referrers/{dg}"), ("tag-schema", f"https://ghcr.io/v2/{repo}/manifests/sha256-{dg[7:]}"), ("tags", f"https://ghcr.io/v2/{repo}/tags/list")):
        s, h, c = req(url, A)
        print("--", rotulo, s, h.get("Content-Type"))
        print(c[:3000].decode("utf-8", "replace"))
