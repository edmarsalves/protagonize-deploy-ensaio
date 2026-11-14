"""Estado persistente (máquina de estados), quarentena, seq monotônico e AUDITORIA encadeada por hash.

• Todo write é atômico (tmp + fsync + rename). Estado corrompido é movido de lado e o agente PARA (não adivinha).
• A auditoria é só de acréscimo; cada linha leva o SHA-256 da anterior (detecta adulteração/remoção no meio).
• Nenhum texto gravado aqui passa sem o Redator (credenciais nunca entram no estado nem na auditoria).
"""
from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import shutil
from datetime import datetime

from .util import (
    EstadoCorrompido,
    REDATOR,
    ErroValidacao,
    agora_utc,
    escrever_atomico,
    exigir_chaves_exatas,
    exigir_digest,
    exigir_inteiro,
    iso_utc,
    json_estrito,
    ler_arquivo_seguro,
    sha256_hex,
    RE_HEX64,
)

RE_IMAGEM_ENV_ESTADO = re.compile(r"\A[A-Za-z0-9.:/_-]{3,200}@sha256\Z")
FASES = ("OCIOSO", "RECEBIDO", "BACKUP", "BAIXANDO", "TROCANDO", "VALIDANDO", "REVERTENDO", "FALHA_CRITICA")
FASES_SEM_TROCA = ("RECEBIDO", "BACKUP", "BAIXANDO")  # nada foi alterado ainda
STATUS_PUBLICOS = ("em_andamento", "ok", "sem_mudanca", "revertido", "falhou_critico", "recusado", "adiado")


def estado_inicial() -> dict:
    return {"versao": 1, "seq_atual": 0, "fase": "OCIOSO", "em_curso": None, "tentativas": {}, "quarentena": [], "ultimo_resultado": None}


def _validar_ref_servicos(obj, campo):
    if obj is None:
        return None
    exigir_chaves_exatas(obj, set(), {"api", "web"}, campo)
    for k, v in obj.items():
        if v is not None:
            exigir_digest(v, f"{campo}.{k}")
    return obj


def _validar_env_antes(obj) -> None:
    """env_antes = {svc: [imagem@sha256, hex]}: o que estava no .env ANTES (para a reversão exata)."""
    exigir_chaves_exatas(obj, set(), {"api", "web"}, "em_curso.env_antes")
    for svc, par in obj.items():
        if not (isinstance(par, list) and len(par) == 2 and all(isinstance(x, str) for x in par)):
            raise EstadoCorrompido("env_antes inválido")
        if not RE_IMAGEM_ENV_ESTADO.match(par[0]) or not RE_HEX64.match(par[1]):
            raise EstadoCorrompido("env_antes com valor fora do formato")


def validar_estado(obj) -> dict:
    exigir_chaves_exatas(obj, set(estado_inicial().keys()), set(), "estado")
    if type(obj["versao"]) is not int or obj["versao"] != 1:
        raise EstadoCorrompido("versão do estado desconhecida")
    exigir_inteiro(obj["seq_atual"], "estado.seq_atual", 0)
    if obj["fase"] not in FASES:
        raise EstadoCorrompido("fase inválida")
    ec = obj["em_curso"]
    if ec is not None:
        exigir_chaves_exatas(ec, {"seq", "digest_ponteiro", "commit", "antes", "env_antes", "alvo", "servicos", "iniciado_em"}, set(), "estado.em_curso")
        exigir_inteiro(ec["seq"], "em_curso.seq")
        exigir_digest(ec["digest_ponteiro"], "em_curso.digest_ponteiro")
        _validar_ref_servicos(ec["antes"], "em_curso.antes")
        _validar_env_antes(ec["env_antes"])
        _validar_ref_servicos(ec["alvo"], "em_curso.alvo")
        if not isinstance(ec["servicos"], list) or any(s not in ("api", "web") for s in ec["servicos"]):
            raise EstadoCorrompido("em_curso.servicos inválido")
    if not isinstance(obj["tentativas"], dict) or any((not re.fullmatch(r"[0-9]{1,16}", k) or type(v) is not int) for k, v in obj["tentativas"].items()):
        raise EstadoCorrompido("tentativas inválidas")
    if not isinstance(obj["quarentena"], list):
        raise EstadoCorrompido("quarentena inválida")
    for d in obj["quarentena"]:
        exigir_digest(d, "quarentena[]")
    if obj["ultimo_resultado"] is not None and not isinstance(obj["ultimo_resultado"], dict):
        raise EstadoCorrompido("ultimo_resultado inválido")
    return obj


class Estado:
    def __init__(self, caminho: str, relogio=agora_utc):
        self.caminho = caminho
        self.relogio = relogio
        self.dados = estado_inicial()

    # ─── persistência ───
    # ÂNCORA independente do seq: um segundo arquivo (só cresce) impede que um estado perdido/corrompido/zerado "libere" replay e downgrade.
    def _ancora_caminho(self) -> str:
        return self.caminho + ".ancora"

    def _ler_ancora(self) -> int:
        p = self._ancora_caminho()
        if not os.path.lexists(p):
            return 0
        try:
            txt = ler_arquivo_seguro(p, 32).decode("ascii").strip()
            if not re.fullmatch(r"[0-9]{1,16}", txt):
                raise ValueError("formato")
            return int(txt)
        except (ErroValidacao, ValueError, UnicodeDecodeError) as e:
            raise EstadoCorrompido("âncora de seq ilegível: o agente PARA até decisão humana") from e

    def carregar(self) -> dict:
        ancora = self._ler_ancora()
        if not os.path.lexists(self.caminho):
            if ancora > 0:
                raise EstadoCorrompido("o estado sumiu mas existe âncora de seq: o agente PARA (um estado ausente NÃO libera replay)")
            self.dados = estado_inicial()
            return self.dados
        try:
            bruto = ler_arquivo_seguro(self.caminho, 64 * 1024)
            self.dados = validar_estado(json_estrito(bruto, 64 * 1024))
        except (ErroValidacao, EstadoCorrompido) as e:
            # NUNCA reinicia sozinho: guarda uma CÓPIA como evidência, MANTÉM o arquivo no lugar e PARA em toda execução até um comando humano
            try:
                shutil.copy2(self.caminho, f"{self.caminho}.suspeito-{self.relogio().strftime('%Y%m%dT%H%M%SZ')}")
            except OSError:
                pass
            raise EstadoCorrompido(f"estado ilegível (o agente PARA até decisão humana): {REDATOR.limpar(e)}") from e
        if self.dados["seq_atual"] < ancora:
            raise EstadoCorrompido("seq_atual abaixo da âncora: estado revertido/adulterado; o agente PARA")
        return self.dados

    def salvar(self) -> None:
        if self.dados["seq_atual"] > self._ler_ancora():
            escrever_atomico(self._ancora_caminho(), str(self.dados["seq_atual"]).encode("ascii"), 0o600)  # âncora ANTES do estado
        escrever_atomico(self.caminho, json.dumps(REDATOR.limpar_obj(self.dados), sort_keys=True, indent=1).encode("utf-8"), 0o600)

    def reinicializar(self) -> int:
        """Comando HUMANO (e auditado pelo chamador): descarta o estado ilegível/ausente e recomeça com seq_atual = âncora (nunca menos)."""
        ancora = self._ler_ancora()
        if os.path.lexists(self.caminho):
            os.replace(self.caminho, f"{self.caminho}.descartado-{self.relogio().strftime('%Y%m%dT%H%M%SZ')}")
        self.dados = estado_inicial()
        self.dados["seq_atual"] = ancora
        self.salvar()
        return ancora

    # ─── operações ───
    @property
    def seq_atual(self) -> int:
        return self.dados["seq_atual"]

    @property
    def fase(self) -> str:
        return self.dados["fase"]

    def em_quarentena(self, digest: str) -> bool:
        return digest in self.dados["quarentena"]

    def quarentenar(self, digests) -> None:
        for d in digests:
            if d not in self.dados["quarentena"]:
                self.dados["quarentena"].append(d)
        self.dados["quarentena"] = self.dados["quarentena"][-200:]
        self.salvar()

    def contar_tentativa(self, seq: int) -> int:
        k = str(seq)
        self.dados["tentativas"][k] = self.dados["tentativas"].get(k, 0) + 1
        # mantém só as últimas 50 sequências
        if len(self.dados["tentativas"]) > 50:
            for velho in sorted(self.dados["tentativas"], key=int)[:-50]:
                del self.dados["tentativas"][velho]
        self.salvar()
        return self.dados["tentativas"][k]

    def iniciar(self, versao, antes: dict, env_antes: dict, servicos: list) -> None:
        self.dados["em_curso"] = {
            "seq": versao.seq, "digest_ponteiro": versao.digest_ponteiro, "commit": versao.commit,
            "antes": dict(antes), "env_antes": {k: list(v) for k, v in env_antes.items()}, "alvo": dict(versao.alvos), "servicos": list(servicos), "iniciado_em": iso_utc(self.relogio()),
        }
        self.dados["fase"] = "RECEBIDO"
        self.salvar()

    def fase_para(self, fase: str) -> None:
        if fase not in FASES:
            raise ValueError("fase inválida")
        self.dados["fase"] = fase
        self.salvar()

    def encerrar(self, resultado: dict, *, consumir_seq: bool, fase_final: str = "OCIOSO") -> None:
        ec = self.dados["em_curso"]
        if consumir_seq:
            seq = ec["seq"] if ec is not None else resultado.get("seq")
            if seq is not None:
                self.dados["seq_atual"] = max(self.dados["seq_atual"], int(seq))
        self.dados["ultimo_resultado"] = REDATOR.limpar_obj(resultado)
        self.dados["em_curso"] = None if fase_final != "FALHA_CRITICA" else ec
        self.dados["fase"] = fase_final
        self.salvar()


class Auditoria:
    """JSONL só de acréscimo, encadeado por hash. Uma linha por decisão.
    • lê só o FIM do arquivo (custo constante); uma linha final cortada NÃO trava para sempre: registra uma 'quebra_de_cadeia' e segue;
    • verificar_cadeia aceita a quebra REGISTRADA (linha ilegível seguida de 'quebra_de_cadeia' ligada ao último registro bom) e recusa o resto."""

    GENESE = "0" * 64
    MAX_LINHA = 16384

    def __init__(self, caminho: str, relogio=agora_utc):
        self.caminho = caminho
        self.relogio = relogio

    def _ultima(self) -> tuple[int, str, bool, bool]:
        """(idx, hash, cauda_ilegivel, falta_quebra_de_linha)"""
        if not os.path.exists(self.caminho):
            return 0, self.GENESE, False, False
        with open(self.caminho, "rb") as f:
            f.seek(0, os.SEEK_END)
            tam = f.tell()
            f.seek(max(0, tam - 65536))
            cauda = f.read()
        sem_nl = bool(cauda) and not cauda.endswith(b"\n")
        linhas = [l for l in cauda.split(b"\n") if l.strip()]
        ilegivel = False
        for linha in reversed(linhas):
            try:
                reg = json.loads(linha)
                return int(reg["idx"]), reg["hash"], ilegivel, sem_nl
            except (ValueError, KeyError, TypeError):
                ilegivel = True
        return 0, self.GENESE, bool(linhas), sem_nl

    @staticmethod
    def _hash(corpo: dict) -> str:
        sem = {k: v for k, v in corpo.items() if k != "hash"}
        return sha256_hex(json.dumps(sem, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))

    def _escrever(self, fd: int, idx: int, anterior: str, evento: str, dados: dict) -> dict:
        corpo = {"idx": idx + 1, "ts": iso_utc(self.relogio()), "evento": REDATOR.limpar(evento)[:80], "dados": REDATOR.limpar_obj(dados), "anterior": anterior}
        corpo["hash"] = self._hash(corpo)
        linha = (json.dumps(corpo, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(linha) > self.MAX_LINHA:  # texto controlado por terceiros não pode inflar a trilha
            corpo["dados"] = {"truncado": True}
            corpo["hash"] = self._hash(corpo)
            linha = (json.dumps(corpo, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode("utf-8")
        os.write(fd, linha)
        os.fsync(fd)
        return corpo

    def registrar(self, evento: str, **dados) -> dict:
        os.makedirs(os.path.dirname(os.path.abspath(self.caminho)), exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
        fd = os.open(self.caminho, flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            idx, anterior, quebra, sem_nl = self._ultima()
            if sem_nl:
                os.write(fd, b"\n")  # fecha a linha cortada: o próximo registro nunca fica colado nela
            if quebra:
                q = self._escrever(fd, idx, anterior, "quebra_de_cadeia", {"motivo": "cauda ilegível (corte/ENOSPC)"})
                idx, anterior = q["idx"], q["hash"]
            return self._escrever(fd, idx, anterior, evento, dados)
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def verificar_cadeia(self) -> tuple[bool, str]:
        """(ok, motivo). Detecta linha adulterada, removida ou reordenada. Aceita APENAS uma quebra registrada depois de linha ilegível."""
        if not os.path.exists(self.caminho):
            return True, "vazia"
        anterior, esperado_idx, pendente_quebra, quebras = self.GENESE, 1, False, 0
        with open(self.caminho, "rb") as f:
            for n, linha in enumerate(f, 1):
                if not linha.strip():
                    continue
                try:
                    reg = json.loads(linha)
                    h = reg.pop("hash")
                except (ValueError, KeyError, TypeError):
                    pendente_quebra = True  # só tolerada se a PRÓXIMA linha boa for uma 'quebra_de_cadeia' ligada ao último registro bom
                    continue
                if pendente_quebra:
                    if reg.get("evento") != "quebra_de_cadeia" or reg.get("anterior") != anterior:
                        return False, f"linha ilegível sem quebra registrada antes da linha {n}"
                    pendente_quebra, quebras = False, quebras + 1
                    esperado_idx = reg.get("idx", esperado_idx)
                if reg.get("idx") != esperado_idx:
                    return False, f"índice fora de ordem na linha {n}"
                if reg.get("anterior") != anterior:
                    return False, f"encadeamento quebrado na linha {n}"
                if self._hash(reg) != h:
                    return False, f"conteúdo adulterado na linha {n}"
                anterior, esperado_idx = h, esperado_idx + 1
        if pendente_quebra:
            return False, "cauda ilegível ainda sem quebra registrada"
        return True, "íntegra" + (f" ({quebras} quebra(s) registrada(s))" if quebras else "")


def gravar_status_publico(caminho: str, *, seq, commit, ponteiro, tentativa: int, status: str, motivo: str, relogio=agora_utc) -> None:
    """Arquivo estático lido pelo job final do GitHub. NUNCA contém segredo nem texto livre longo."""
    if status not in STATUS_PUBLICOS:
        raise ValueError("status inválido")
    doc = {
        "esquema": 1, "seq": seq, "commit": commit, "ponteiro": ponteiro, "tentativa": tentativa, "status": status,
        "motivo": (REDATOR.limpar(motivo)[:120]), "gerado_em": iso_utc(relogio()),
        "concluido_em": iso_utc(relogio()) if status in ("ok", "sem_mudanca", "revertido", "falhou_critico", "recusado") else None,
    }
    escrever_atomico(caminho, json.dumps(doc, sort_keys=True).encode("utf-8"), 0o644)
