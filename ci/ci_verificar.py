#!/usr/bin/env python3
"""Dentro do GitHub Actions (ENSAIO): baixa do GHCR o que o fluxo acabou de publicar e o VERIFICA exatamente como o agente faria
(mesmo código, cosign REAL, raiz de confiança FIXADA). Faz também controles NEGATIVOS: versões autênticas porém NÃO autorizadas têm de ser recusadas.
Não imprime nem grava nenhum segredo. Sai com código != 0 se o positivo falhar ou se QUALQUER negativo for aceito."""
import copy, dataclasses, json, os, sys, traceback
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agente_src"))
from agente.atestado import BackendCosign, verificar_pacote
from agente.politica import validar_politica
from agente.registro import ClienteGHCR
from agente.util import REDATOR, digest_de, json_estrito

E = os.environ
EVID = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidencias")
os.makedirs(EVID, exist_ok=True)
REDATOR.registrar(E["GITHUB_TOKEN"])
dono = E["GITHUB_REPOSITORY_OWNER"].lower()
repo = E["GITHUB_REPOSITORY"]
evento = E["GITHUB_EVENT_NAME"]
WORKFLOW = E.get("WORKFLOW_PATH", ".github/workflows/deploy-hostinger-ensaio.yml")
PREF = E.get("PREFIXO_IMAGEM", "ensaio")
BASE = {"registro": "ghcr.io", "namespace": dono, "imagens": {"api": f"{PREF}-api", "web": f"{PREF}-web", "release": f"{PREF}-release"}, "repositorio": repo,
        "repositorio_id": E["REPO_ID"], "dono_id": E["OWNER_ID"], "workflow": WORKFLOW, "ref": "refs/heads/main",
        "emissor": "https://token.actions.githubusercontent.com", "eventos": [evento], "exigir_runner_hospedado": True,
        "validade_ponteiro_s": 3600, "tolerancia_relogio_s": 300, "max_tentativas": 3, "servicos": ["api", "web"], "tag_ponteiro": "prod"}
COSIGN, RAIZ = "/tmp/cosign", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ferramentas", "trusted_root.json")
RAIZ = os.path.abspath(RAIZ)
res = {"quando": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "evento": evento, "repositorio": repo, "positivo": None, "negativos": [], "observacoes": {}}


def politica(**alt):
    d = copy.deepcopy(BASE); d.update(alt); return validar_politica(d)


def cliente():
    return ClienteGHCR("https://ghcr.io", E["GITHUB_ACTOR"], lambda: E["GITHUB_TOKEN"], tempo_limite=30)


def pacote(pol, cli, alvo_ponteiro_digest):
    rel = pol.nome_imagem("release").split("/", 1)[1]
    bruto = cli.baixar_ponteiro(rel, alvo_ponteiro_digest)
    if digest_de(bruto) != alvo_ponteiro_digest:
        raise RuntimeError("o manifesto do ponteiro não bate com o digest anunciado")
    ptr = json.loads(bruto)
    arq = {"ponteiro.json": bruto, "ponteiro.atestado.json": cli.baixar_atestado(rel, alvo_ponteiro_digest)}
    for svc in ("api", "web"):
        d = ptr["annotations"].get(f"br.protagonize.{svc}")
        if d:
            arq[f"{svc}.atestado.json"] = cli.baixar_atestado(pol.nome_imagem(svc).split("/", 1)[1], d)
    return arq, ptr


def verificar(pol, arq):
    return verificar_pacote(arq, pol, BackendCosign(pol, COSIGN, tempo_limite=120, trusted_root=RAIZ), datetime.now(timezone.utc))


def main() -> int:
    ok = True
    pol, cli = politica(), cliente()
    rel = pol.nome_imagem("release").split("/", 1)[1]
    try:
        anunciado = cli.digest_do_ponteiro(rel, "prod")
        res["observacoes"]["ponteiro_anunciado_igual_ao_publicado_por_este_run"] = (anunciado == E["PONTEIRO_DIGEST"])
        arq, ptr = pacote(pol, cli, E["PONTEIRO_DIGEST"])
        res["observacoes"]["anotacoes_reais_do_ponteiro"] = sorted(ptr.get("annotations", {}).keys())
        res["observacoes"]["tamanhos_atestados"] = {k: len(v) for k, v in arq.items() if k.endswith("atestado.json")}
        v = verificar(pol, arq)
        res["positivo"] = {"ok": True, "seq": v.seq, "commit": v.commit, "gatilho": v.gatilho, "alvos": v.alvos}
        if str(v.seq) != E["GITHUB_RUN_ID"] or v.commit != E["GITHUB_SHA"]:
            res["positivo"]["ok"] = False; ok = False
    except Exception as e:  # noqa: BLE001
        res["positivo"] = {"ok": False, "erro": REDATOR.limpar(f"{type(e).__name__}: {e}")[:300]}
        traceback.print_exc(limit=2); ok = False; arq = None

    def negativo(nome, fn):
        try:
            fn()
            res["negativos"].append({"caso": nome, "recusado": False}); return False
        except Exception as e:  # noqa: BLE001
            res["negativos"].append({"caso": nome, "recusado": True, "tipo": type(e).__name__, "codigo": getattr(e, "codigo", None)}); return True

    if arq:
        m0 = json.loads(arq['ponteiro.json'])
        adulterado = dict(arq); m = json.loads(arq["ponteiro.json"]); m["annotations"]["br.protagonize.seq"] = str(int(m["annotations"]["br.protagonize.seq"]) + 1)
        adulterado["ponteiro.json"] = json.dumps(m, sort_keys=True).encode()
        casos = [("repositório diferente na política", lambda: verificar(politica(repositorio="atacante/" + repo.split("/")[1]), arq)),
                 ("ref/branch diferente", lambda: verificar(politica(ref="refs/heads/outra"), arq)),
                 ("workflow diferente", lambda: verificar(politica(workflow=".github/workflows/outro.yml"), arq)),
                 ("ID imutável do repositório diferente (cosign aprova, política recusa)", lambda: verificar(politica(repositorio_id="1"), arq)),
                 ("ID imutável do dono diferente", lambda: verificar(politica(dono_id="1"), arq)),
                 ("gatilho não permitido pela política", lambda: verificar(politica(eventos=["workflow_dispatch" if evento != "workflow_dispatch" else "push"]), arq)),
                 ("ponteiro com seq elevado (adulterado)", lambda: verificar(pol, adulterado)),
                 ("sem atestado de imagem", lambda: verificar(pol, {k: v for k, v in arq.items() if not k.startswith(("api.", "web."))})),
                 ("assinatura ausente no ponteiro", lambda: verificar(pol, {k: v for k, v in arq.items() if k != "ponteiro.atestado.json"})),
                 ("digest da imagem adulterado no pacote (o atestado não cobre)", lambda: verificar(pol, dict(arq, **{"ponteiro.json": json.dumps(dict(m0, annotations=dict(m0["annotations"], **{"br.protagonize.api": "sha256:" + "0" * 64})), sort_keys=True).encode()}))),
                 ("atestado de OUTRA imagem legítima no lugar (web no lugar da api)", lambda: verificar(pol, dict(arq, **{"api.atestado.json": arq["web.atestado.json"]})))]
        for nome, fn in casos:
            if not negativo(nome, fn):
                ok = False
    try:  # IDENTIDADE NÃO AUTORIZADA: outro workflow do MESMO repositório assinou (assinatura válida) a sua própria imagem
        dono_repo = f"{dono}/{PREF}-intruso"
        di = cli.digest_do_ponteiro(dono_repo, "ultimo")
        if di:
            bi = cli.baixar_atestado(dono_repo, di)
            from agente.atestado import EsperadoCertificado
            commit_i = None
            import base64 as _b
            decl = json.loads(_b.b64decode(json.loads(bi)["dsseEnvelope"]["payload"]))
            commit_i = decl["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"]
            esp = EsperadoCertificado(commit=commit_i, gatilho="workflow_dispatch")
            intruso = {"digest": di}
            try:  # 1) sob a política LEGÍTIMA o cosign recusa (identidade do certificado ≠ workflow autorizado)
                BackendCosign(politica(eventos=["workflow_dispatch"]), COSIGN, tempo_limite=120, trusted_root=RAIZ).verificar(bi, di, esp)
                intruso["recusado_pela_politica_legitima"] = False; ok = False
            except Exception as e:  # noqa: BLE001
                intruso["recusado_pela_politica_legitima"] = True; intruso["motivo"] = type(e).__name__
            # 2) sob uma política que declara a identidade do intruso a assinatura é VÁLIDA (prova de que a recusa acima foi por IDENTIDADE, não por defeito)
            pol_i = politica(workflow=".github/workflows/keyless-intruso.yml", eventos=["workflow_dispatch"])
            BackendCosign(pol_i, COSIGN, tempo_limite=120, trusted_root=RAIZ).verificar(bi, di, esp)
            intruso["assinatura_valida_sob_a_propria_identidade"] = True
            res["intruso"] = intruso
        else:
            res["intruso"] = "sem imagem do intruso (workflow ainda não executado)"
    except Exception as e:  # noqa: BLE001
        res["intruso"] = {"erro": REDATOR.limpar(f"{type(e).__name__}: {e}")[:300]}; ok = False
    with open(os.path.join(EVID, E.get("NOME_RESULTADO", "resultado.json")), "w") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    print(json.dumps({"positivo": res["positivo"], "negativos_recusados": sum(1 for n in res["negativos"] if n["recusado"]), "negativos_total": len(res["negativos"])}, ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
