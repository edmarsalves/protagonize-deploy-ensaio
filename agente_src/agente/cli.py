"""Linha de comando: `python -m agente executor|verificador --config ARQUIVO.json [--uma-vez]`.

A configuração é um arquivo LOCAL da VPS (root), com chaves exatas e SOMENTE caminhos absolutos. Nada vem do repositório.
Neste Lote 2 a CLI é validada por testes de configuração; a execução contra o Docker/GHCR/cosign reais é objeto do Lote 4.
"""
from __future__ import annotations

import argparse
import os
import sys

from .acoes import ConfigDocker, PlataformaDocker, PlataformaSimulada
from .atestado import BackendCosign
from .estado import Auditoria, Estado
from .executor import CODIGOS_SAIDA, ConfigExecutor, Executor
from .politica import carregar_politica
from .registro import ClienteGHCR
from .util import REDATOR, ErroAgente, ErroValidacao, carregar_token, exigir_chaves_exatas, json_estrito, ler_arquivo_seguro
from .verificador import ConfigVerificador, Verificador

CHAVES_EXECUTOR = {
    "politica", "estado", "auditoria", "entrada", "quarentena_pacotes", "status_publico", "pausar", "trava", "token", "cosign", "trusted_root",
    "docker", "env_file", "chaves_env", "compose_arquivos", "containers", "checkpoint_cmd", "validacoes",
}
CHAVES_VERIFICADOR = {"politica", "entrada", "estado", "status_publico", "auditoria", "token", "cosign", "trusted_root", "registro_url", "registro_usuario"}


def _abs(valor, campo):
    if not isinstance(valor, str) or not os.path.isabs(valor) or ".." in valor.split(os.sep):
        raise ErroValidacao(f"{campo}: caminho absoluto sem '..' esperado")
    return valor


def carregar_config(caminho: str, chaves: set) -> dict:
    cfg = json_estrito(ler_arquivo_seguro(caminho, 32 * 1024, proibir_escrita_outros=True), 32 * 1024)
    exigir_chaves_exatas(cfg, chaves - {"cosign", "docker", "registro_url", "registro_usuario"}, chaves, "config")
    for k, v in cfg.items():
        if k in ("compose_arquivos",):
            [_abs(x, k) for x in v]
        elif k in ("containers", "validacoes", "checkpoint_cmd", "registro_url", "registro_usuario"):
            continue
        else:
            _abs(v, k)
    return cfg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="agente")
    ap.add_argument("componente", choices=["executor", "verificador", "reconhecer-falha-critica"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--simulado", help="pasta descartável de uma PlataformaSimulada (somente executor)")
    ap.add_argument("--operador", default="")
    a = ap.parse_args(argv)
    try:
        if a.componente == "verificador":
            c = carregar_config(a.config, CHAVES_VERIFICADOR)
            pol = carregar_politica(c["politica"])
            token = carregar_token(c["token"])
            cli = ClienteGHCR(c.get("registro_url", "https://ghcr.io"), c.get("registro_usuario", "conta-de-servico"), lambda: token)
            v = Verificador(pol, ConfigVerificador(c["entrada"], c["estado"], c["status_publico"]), cli, BackendCosign(pol, c.get("cosign", "/usr/local/bin/cosign"), trusted_root=c["trusted_root"]),
                            Auditoria(c["auditoria"]))
            print(v.ciclo())
            return 0
        c = carregar_config(a.config, CHAVES_EXECUTOR)
        pol = carregar_politica(c["politica"])
        estado, aud = Estado(c["estado"]), Auditoria(c["auditoria"])
        if a.simulado:
            plat = PlataformaSimulada(_abs(a.simulado, "--simulado"), pol)
        else:
            cfgd = ConfigDocker(docker_bin=c.get("docker", "/usr/bin/docker"), env_file=c["env_file"], chaves_env=c["chaves_env"], compose_arquivos=c["compose_arquivos"],
                                containers=c["containers"], checkpoint_cmd=c["checkpoint_cmd"], validacoes=c["validacoes"])
            plat = PlataformaDocker(cfgd, pol)
        ex = Executor(pol, ConfigExecutor(c["entrada"], c["quarentena_pacotes"], c["status_publico"], c["pausar"], c["trava"]), estado, aud, plat,
                      BackendCosign(pol, c.get("cosign", "/usr/local/bin/cosign"), trusted_root=c["trusted_root"]), token_fn=lambda: carregar_token(c["token"]))
        if a.componente == "reconhecer-falha-critica":
            ex.reconhecer_falha_critica(a.operador or "operador-desconhecido")
            return 0
        r = ex.executar_uma_vez()
        print(r)
        return CODIGOS_SAIDA[r]
    except ErroValidacao as e:
        print(f"configuração/entrada inválida: {REDATOR.limpar(e)}", file=sys.stderr)
        return 64
    except ErroAgente as e:
        print(f"erro do agente: {REDATOR.limpar(e)}", file=sys.stderr)
        return 70


if __name__ == "__main__":
    sys.exit(main())
