"""Canal verificador → executor: um diretório-pacote entregue de forma ATÔMICA e lido como INSTANTÂNEO.

Ameaças tratadas:
  • adulteração/substituição de arquivo (symlink, hardlink, FIFO, arquivo extra, nome com '../', arquivo gigante);
  • corrida TOCTOU: o executor LÊ UMA VEZ cada arquivo para a memória (O_NOFOLLOW, sem seguir link, limite de tamanho)
    e só usa esses bytes depois (verifica e age sobre a MESMA cópia); o diretório de origem é descartado;
  • pacote incompleto: o verificador monta tudo num diretório temporário e só então faz rename atômico;
  • reprocessamento: o executor MOVE o pacote para fora da pasta compartilhada antes de ler.
Mesmo que o verificador (que fala com a rede) seja comprometido, o executor RE-VERIFICA tudo (atestado e política).
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
import tempfile

from .atestado import MAX_ATESTADO, NOMES_PACOTE
from .util import ErroValidacao, escrever_atomico, ler_arquivo_seguro

RE_PACOTE = re.compile(r"\Apedido-[0-9]{1,16}-[0-9a-f]{16}\Z")
LIMITES = {"ponteiro.json": 4096, "meta.json": 4096, "ponteiro.atestado.json": MAX_ATESTADO, "api.atestado.json": MAX_ATESTADO, "web.atestado.json": MAX_ATESTADO}
TOTAL_MAX = 3 * MAX_ATESTADO + 16 * 1024


def entregar_pacote(entrada: str, seq: int, arquivos: dict) -> str:
    """(verificador) Monta e publica o pacote atomicamente. Só aceita nomes da lista fixa."""
    for nome, dados in arquivos.items():
        if nome not in NOMES_PACOTE or not isinstance(dados, (bytes, bytearray)):
            raise ErroValidacao("arquivo de pacote não permitido")
        if len(dados) > LIMITES[nome]:
            raise ErroValidacao("arquivo de pacote grande demais")
    os.makedirs(entrada, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix=".tmp-pedido-", dir=entrada)
    try:
        os.chmod(tmp, 0o750)
        for nome, dados in arquivos.items():
            escrever_atomico(os.path.join(tmp, nome), bytes(dados), 0o640)
        destino = os.path.join(entrada, f"pedido-{int(seq)}-{secrets.token_hex(8)}")
        os.rename(tmp, destino)  # atômico: o executor nunca vê pacote pela metade
        return destino
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def listar_pacotes(entrada: str) -> list:
    if not os.path.isdir(entrada):
        return []
    achados = []
    for nome in sorted(os.listdir(entrada)):
        if RE_PACOTE.match(nome):
            achados.append(os.path.join(entrada, nome))
    return achados


def reivindicar_pacote(caminho: str, quarentena_dir: str, *, uid_confiavel: int | None = None) -> dict:
    """(executor) Lê o pacote como instantâneo seguro e remove o original. Lança ErroValidacao se qualquer regra falhar.

    Em caso de recusa, o pacote suspeito é MOVIDO para a quarentena (evidência), nunca executado.
    """
    try:
        st = os.lstat(caminho)
        if not stat.S_ISDIR(st.st_mode):
            raise ErroValidacao("pacote não é diretório (symlink/arquivo)")
        if uid_confiavel is not None and st.st_uid != uid_confiavel:
            raise ErroValidacao("dono do pacote não é o esperado")
        nomes = sorted(os.listdir(caminho))
        if not nomes or len(nomes) > len(NOMES_PACOTE):
            raise ErroValidacao("quantidade de arquivos fora do permitido")
        total = 0
        instantaneo = {}
        for nome in nomes:
            if nome not in NOMES_PACOTE:
                raise ErroValidacao(f"arquivo não permitido no pacote: {nome!r}")
            dados = ler_arquivo_seguro(os.path.join(caminho, nome), LIMITES[nome], uid_dono=uid_confiavel)
            total += len(dados)
            if total > TOTAL_MAX:
                raise ErroValidacao("pacote grande demais")
            instantaneo[nome] = dados
        return instantaneo
    except ErroValidacao:
        _mover_para_quarentena(caminho, quarentena_dir)
        raise
    except OSError as e:
        _mover_para_quarentena(caminho, quarentena_dir)
        raise ErroValidacao(f"pacote ilegível ({e.strerror})") from e
    finally:
        # sucesso: o instantâneo está em memória; descarta o original (nunca reutilizado)
        if os.path.lexists(caminho):
            try:
                if os.path.isdir(caminho) and not os.path.islink(caminho):
                    shutil.rmtree(caminho, ignore_errors=True)
                else:
                    os.unlink(caminho)
            except OSError:
                pass


def _mover_para_quarentena(caminho: str, quarentena_dir: str) -> None:
    try:
        os.makedirs(quarentena_dir, exist_ok=True)
        os.chmod(quarentena_dir, 0o700)
        destino = os.path.join(quarentena_dir, os.path.basename(caminho) + "-" + secrets.token_hex(4))
        if os.path.islink(caminho) or not os.path.isdir(caminho):
            os.unlink(caminho)  # link/arquivo: apenas remove (não segue)
        else:
            os.rename(caminho, destino)
    except OSError:
        pass


def limpar_temporarios(entrada: str, idade_s: int = 600) -> int:
    """Remove '.tmp-pedido-*' esquecidos por um verificador que caiu (eles mantinham o acionamento por 'diretório não vazio')."""
    import time
    n = 0
    if not os.path.isdir(entrada):
        return 0
    for nome in os.listdir(entrada):
        if nome.startswith(".tmp-pedido-"):
            caminho = os.path.join(entrada, nome)
            try:
                if time.time() - os.lstat(caminho).st_mtime > idade_s and not os.path.islink(caminho):
                    shutil.rmtree(caminho, ignore_errors=True)
                    n += 1
            except OSError:
                pass
    return n


def podar_quarentena(quarentena_dir: str, manter: int = 50) -> int:
    """A quarentena de pacotes não pode crescer sem limite: mantém só os 'manter' mais novos (o resto está na auditoria)."""
    if not os.path.isdir(quarentena_dir):
        return 0
    itens = sorted((os.path.join(quarentena_dir, n) for n in os.listdir(quarentena_dir)), key=lambda p: os.lstat(p).st_mtime)
    removidos = 0
    for p in itens[:-manter] if len(itens) > manter else []:
        try:
            shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) and not os.path.islink(p) else os.unlink(p)
            removidos += 1
        except OSError:
            pass
    return removidos
