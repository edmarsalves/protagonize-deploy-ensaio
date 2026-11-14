#!/usr/bin/env python3
"""ENSAIO REAL do O1 (OIDC). O JWT NUNCA é impresso, gravado, enviado a registro ou colocado em artefato: vive só na memória deste processo.
Sai com código != 0 se algum controle falhar. Evidências: somente claims (não secretas), tempos e resultados em evidencias/oidc/resultado-oidc.json."""
import copy, hashlib, json, os, sys, time, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from oidc_prototipo import (EMISSOR, JwksCliente, JwksIndisponivel, TokenInvalido, audiencia_do_manifesto, autorizar, verificar_com_jwks, verificar_token, _b64u, _json)

E = os.environ
EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidencias", "oidc"); os.makedirs(EVID, exist_ok=True)
SEGREDOS = []  # strings que jamais podem aparecer em saída
res = {"quando": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "run_id": E["GITHUB_RUN_ID"], "run_attempt": E["GITHUB_RUN_ATTEMPT"], "testes": {}}
ok_geral = True


def registrar(nome, ok, detalhe=None):
    global ok_geral
    res["testes"][nome] = {"ok": bool(ok), **({"detalhe": detalhe} if detalhe is not None else {})}
    ok_geral = ok_geral and bool(ok)
    print(("PASSOU  " if ok else "FALHOU  ") + nome + ("" if detalhe is None else f" -> {json.dumps(detalhe, ensure_ascii=False)[:300]}"))


def pedir_token(aud):
    """Pede o token OIDC do job. Devolve (token|None, http_status). O token é mascarado no log do Actions antes de qualquer uso."""
    url = E["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + urllib.parse.quote(aud, safe="")
    req = urllib.request.Request(url, headers={"Authorization": "bearer " + E["ACTIONS_ID_TOKEN_REQUEST_TOKEN"], "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as f:
            tok = json.load(f)["value"]
        SEGREDOS.append(tok); print("::add-mask::" + tok)
        return tok, 200
    except urllib.error.HTTPError as e:
        return None, e.code
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def claims_de(tok):
    return _json(_b64u(tok.split(".")[1]))


SEGREDOS.append(E["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]); print("::add-mask::" + E["ACTIONS_ID_TOKEN_REQUEST_TOKEN"])
seq, tent = int(E["GITHUB_RUN_ID"]), int(E["GITHUB_RUN_ATTEMPT"])
MAN = {"esquema": 1, "seq": seq, "tentativa_run": tent, "commit": E["GITHUB_SHA"], "tipo": "release", "gatilho": E["GITHUB_EVENT_NAME"], "criado_em": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
       "api": "sha256:" + "a1" * 32, "web": "sha256:" + "b2" * 32}
MAN_B = json.dumps(MAN, sort_keys=True).encode()
AUD = audiencia_do_manifesto(MAN_B)
POL = {"repositorio": E["GITHUB_REPOSITORY"], "repositorio_id": E["REPO_ID"], "dono_id": E["OWNER_ID"], "workflow": ".github/workflows/oidc-ensaio.yml", "ref": "refs/heads/main",
       "eventos": ["workflow_dispatch", "push"]}
res["audiencia_usada_tamanho"] = len(AUD)

# ── T1: token real, assinatura RS256 contra o JWKS REAL do emissor, claims ──
jw = JwksCliente()
tok, st = pedir_token(AUD)
registrar("t1_token_obtido", tok is not None, {"http": st})
if tok is None:
    sys.exit(1)
cab = _json(_b64u(tok.split(".")[0])); cl = claims_de(tok)
res["cabecalho"] = {k: cab[k] for k in cab if k in ("alg", "typ")} | {"kid_prefixo": str(cab.get("kid"))[:8], "tem_x5t": "x5t" in cab}
res["claims"] = {k: v for k, v in cl.items() if k != "jti"}  # claims não são segredo; sem o JWT inteiro
res["tempos"] = {"exp_menos_iat_s": cl["exp"] - cl["iat"], "nbf_menos_iat_s": cl["nbf"] - cl["iat"], "agora_menos_iat_s": int(time.time()) - cl["iat"]}
try:
    c = verificar_com_jwks(tok, jw, agora=int(time.time()), aud_esperada=AUD)
    registrar("t1_assinatura_rs256_jwks_real_emissor_audiencia_tempo", True, {"chaves_no_jwks": len(jw.cache["keys"]), "kids": [k["kid"][:8] for k in jw.cache["keys"]]})
    registrar("t1_claims_autorizadas_pela_politica", autorizar(c, MAN, POL, seq_atual=seq - 1) == tent, {"run_attempt": c.get("run_attempt")})
except Exception as e:  # noqa: BLE001
    registrar("t1_validacao_real", False, f"{type(e).__name__}: {e}")
    c = None

if c:
    # ── T3/T4: adulteração do manifesto, identidades não autorizadas ──
    trocado = dict(MAN, api="sha256:" + "ff" * 32)
    try:
        verificar_com_jwks(tok, jw, agora=int(time.time()), aud_esperada=audiencia_do_manifesto(json.dumps(trocado, sort_keys=True).encode())); registrar("t3_manifesto_adulterado_recusado", False)
    except TokenInvalido as e:
        registrar("t3_manifesto_adulterado_recusado", e.codigo == "audiencia", e.codigo)
    negs = {"repositorio_nome": dict(POL, repositorio="atacante/x"), "repositorio_id": dict(POL, repositorio_id="1"), "dono_id": dict(POL, dono_id="1"),
            "workflow": dict(POL, workflow=".github/workflows/outro.yml"), "branch": dict(POL, ref="refs/heads/outra"), "evento": dict(POL, eventos=["pull_request"])}
    for nome, pol in negs.items():
        try:
            autorizar(c, MAN, pol, seq - 1); registrar(f"t4_nao_autorizado_{nome}", False)
        except TokenInvalido as e:
            registrar(f"t4_nao_autorizado_{nome}", True, e.codigo)
    for nome, man in {"commit": dict(MAN, commit="0" * 40), "run_id": dict(MAN, seq=seq + 1), "run_attempt": dict(MAN, tentativa_run=tent + 1)}.items():
        try:
            autorizar(c, man, POL, seq - 1); registrar(f"t4_manifesto_inconsistente_{nome}", False)
        except TokenInvalido as e:
            registrar(f"t4_manifesto_inconsistente_{nome}", True, e.codigo)
    for nome, atual in {"replay_mesmo_seq": seq, "downgrade_seq_maior_ja_aplicado": seq + 10}.items():
        try:
            autorizar(c, MAN, POL, atual); registrar(f"t4_{nome}", False)
        except TokenInvalido as e:
            registrar(f"t4_{nome}", e.codigo == "sequencia", e.codigo)

    # ── T2: limites da audiência ──
    lim = {}
    for n in (82, 256, 512, 1024, 2048):
        t2, s2 = pedir_token("protagonize-publicacao:v1:" + "x" * (n - 26))
        lim[str(n)] = "ok" if t2 else f"falhou({s2})"
        if t2:
            lim[str(n)] += f" jwt={len(t2)}B"
    res["limites_audiencia"] = lim
    registrar("t2_audiencia_82_caracteres_aceita", lim["82"].startswith("ok"), lim)

    # ── T6: rotação simulada e indisponibilidade do JWKS ──
    real = jw.cache
    kid = cab["kid"]
    sem = {"keys": [k for k in real["keys"] if k["kid"] != kid]}
    try:
        verificar_token(tok, sem, agora=int(time.time()), aud_esperada=AUD); registrar("t6_rotacao_chave_removida_recusa", False)
    except TokenInvalido as e:
        registrar("t6_rotacao_chave_removida_recusa", e.codigo == "chave", e.codigo)
    novo = JwksCliente(buscar=lambda u: json.dumps({"keys": [k for k in real["keys"] if k["kid"] != kid]}).encode()); novo.buscar = None
    try:
        verificar_com_jwks(tok, novo, agora=int(time.time()), aud_esperada=AUD); registrar("t6_kid_revogado_apos_renovar_recusa", False)
    except TokenInvalido as e:
        registrar("t6_kid_revogado_apos_renovar_recusa", e.codigo == "chave", e.codigo)
    fora = JwksCliente(buscar=lambda u: (_ for _ in ()).throw(OSError("simulado")))
    try:
        verificar_com_jwks(tok, fora, agora=int(time.time()), aud_esperada=AUD); registrar("t6_jwks_indisponivel_sem_cache_nao_aceita", False)
    except JwksIndisponivel:
        registrar("t6_jwks_indisponivel_sem_cache_nao_aceita", True)
    inst = {"n": 0}
    def intermitente(u):
        inst["n"] += 1
        if inst["n"] == 1:
            return json.dumps(real).encode()
        raise OSError("simulado")
    com_cache = JwksCliente(buscar=intermitente, ttl_s=0)
    verificar_com_jwks(tok, com_cache, agora=int(time.time()), aud_esperada=AUD)
    try:
        verificar_com_jwks(tok, com_cache, agora=int(time.time()), aud_esperada=AUD); registrar("t6_jwks_fora_usa_ultima_copia_boa", True)
    except Exception as e:  # noqa: BLE001
        registrar("t6_jwks_fora_usa_ultima_copia_boa", False, str(e))
    err = JwksCliente(url="https://127.0.0.1:9/jwks")
    try:
        err._renovar(); registrar("t6_busca_real_falhando_vira_indisponivel", False)
    except JwksIndisponivel:
        registrar("t6_busca_real_falhando_vira_indisponivel", True)

    # ── T7: expiração REAL ──
    exp = cl["exp"]; esperar = min(max(exp + 61 - int(time.time()), 0), 1500)
    res["tempos"]["esperando_s"] = esperar
    print(f"aguardando {esperar}s até passar do exp real do token…", flush=True); time.sleep(esperar)
    agora = int(time.time())
    try:
        verificar_com_jwks(tok, jw, agora=agora, aud_esperada=AUD); registrar("t7_expirado_modo_portador_recusa", False, {"agora_menos_exp": agora - exp})
    except TokenInvalido as e:
        registrar("t7_expirado_modo_portador_recusa", e.codigo == "tempo", {"codigo": e.codigo, "agora_menos_exp_s": agora - exp})
    try:
        verificar_com_jwks(tok, jw, agora=agora, aud_esperada=AUD, momento_do_manifesto=cl["iat"] + 5, idade_max_s=7 * 86400); registrar("t7_modo_evidencia_aceita_apos_expirar", True)
    except Exception as e:  # noqa: BLE001
        registrar("t7_modo_evidencia_aceita_apos_expirar", False, str(e))

# ── T8: nenhum segredo/JWT em lugar algum ──
texto = json.dumps(res)
vazou = [i for i, s in enumerate(SEGREDOS) if s and s in texto]
registrar("t8_nenhum_token_no_resultado", not vazou)
with open(os.path.join(EVID, "resultado-oidc.json"), "w") as f:
    json.dump(res, f, indent=1, ensure_ascii=False)
print(json.dumps({"ok": ok_geral, "testes": len(res["testes"]), "falhas": [k for k, v in res["testes"].items() if not v["ok"]]}))
sys.exit(0 if ok_geral else 1)
