"""Utilidades de segurança do agente de publicação (somente biblioteca padrão).

Tudo o que processa dado externo (JSON, nomes de arquivo, datas, digests) passa por aqui, com
validação ESTRITA (lista de permissões, nunca lista de bloqueios) e sem nunca montar comando de shell.
"""
from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from typing import Any

# ───────────────────────── exceções ─────────────────────────


class ErroAgente(Exception):
    """Base de todos os erros esperados do agente."""


class ErroValidacao(ErroAgente):
    """Dado externo fora do formato permitido (recusa; nunca 'tenta assim mesmo')."""


class ErroComunicacao(ErroAgente):
    """Falha de rede/registro. transitorio=True ⇒ vale tentar de novo mais tarde (com espera crescente)."""

    def __init__(self, mensagem: str, transitorio: bool = True, retry_apos: float | None = None):
        super().__init__(mensagem)
        self.transitorio = transitorio
        self.retry_apos = retry_apos


class AtestadoInvalido(ErroAgente):
    """Assinatura/atestado ausente, adulterado ou que não cobre o digest pedido."""


class AtestadoIndisponivel(ErroAgente):
    """A ferramenta/rede de verificação falhou (timeout, binário ausente, atestado ainda não publicado). NÃO é 'assinatura inválida': tenta de novo depois."""


class ProvenienciaRejeitada(ErroAgente):
    """O atestado é válido, mas NÃO autoriza: origem diferente da política (repo, workflow, ref, execução…)."""


class Ocupado(ErroAgente):
    """Outra execução detém a trava."""


class EstadoCorrompido(ErroAgente):
    """Arquivo de estado ilegível ou fora do esquema."""


class FalhaCritica(ErroAgente):
    """A reversão também falhou: exige intervenção humana (não há laço de tentativas)."""


# ───────────────────────── formatos ─────────────────────────

RE_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
RE_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
RE_COMMIT = re.compile(r"\A[0-9a-f]{40}\Z")
RE_ISO = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z")
RE_NOME_SEGURO = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")
RE_ID_NUMERICO = re.compile(r"\A[1-9][0-9]{0,19}\Z")
SEQ_MAX = 2**53 - 1


def exigir_digest(valor: Any, campo: str = "digest") -> str:
    if not isinstance(valor, str) or not RE_DIGEST.match(valor):
        raise ErroValidacao(f"{campo}: formato inválido (esperado sha256:<64 hex minúsculos>)")
    return valor


def exigir_commit(valor: Any, campo: str = "commit") -> str:
    if not isinstance(valor, str) or not RE_COMMIT.match(valor):
        raise ErroValidacao(f"{campo}: formato inválido (esperado 40 hex minúsculos)")
    return valor


def exigir_inteiro(valor: Any, campo: str, minimo: int = 1, maximo: int = SEQ_MAX) -> int:
    # bool é subclasse de int em Python: recusar explicitamente
    if isinstance(valor, bool) or not isinstance(valor, int) or not (minimo <= valor <= maximo):
        raise ErroValidacao(f"{campo}: inteiro fora do intervalo permitido")
    return valor


def parse_iso_utc(valor: Any, campo: str = "data") -> datetime:
    if not isinstance(valor, str):
        raise ErroValidacao(f"{campo}: texto esperado")
    m = RE_ISO.match(valor)
    if not m:
        raise ErroValidacao(f"{campo}: use AAAA-MM-DDTHH:MM:SSZ (UTC)")
    try:
        return datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc)
    except ValueError as e:
        raise ErroValidacao(f"{campo}: data inexistente") from e


def iso_utc(momento: datetime) -> str:
    return momento.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def agora_utc() -> datetime:
    return datetime.now(timezone.utc)


def sha256_hex(dados: bytes) -> str:
    return hashlib.sha256(dados).hexdigest()


def digest_de(dados: bytes) -> str:
    return "sha256:" + sha256_hex(dados)


# ───────────────────────── JSON estrito ─────────────────────────


def _pares_unicos(pares):
    saida: dict = {}
    for chave, valor in pares:
        if chave in saida:
            raise ErroValidacao(f"chave JSON duplicada: {chave!r}")
        saida[chave] = valor
    return saida


def _recusar_constante(nome: str):
    raise ErroValidacao(f"constante JSON não permitida: {nome}")


def json_estrito(dados: bytes, max_bytes: int = 256 * 1024) -> Any:
    """JSON UTF-8, sem chaves duplicadas, sem NaN/Infinity, com limite de tamanho e profundidade."""
    if not isinstance(dados, (bytes, bytearray)):
        raise ErroValidacao("JSON: bytes esperados")
    if len(dados) > max_bytes:
        raise ErroValidacao("JSON grande demais")
    try:
        texto = bytes(dados).decode("utf-8")
    except UnicodeDecodeError as e:
        raise ErroValidacao("JSON não é UTF-8 válido") from e
    try:
        return json.loads(texto, object_pairs_hook=_pares_unicos, parse_constant=_recusar_constante)
    except ErroValidacao:
        raise
    except (ValueError, RecursionError) as e:
        raise ErroValidacao("JSON malformado") from e


def exigir_chaves_exatas(obj: Any, obrigatorias: set[str], opcionais: set[str], campo: str) -> dict:
    """O objeto precisa ter TODAS as obrigatórias e nenhuma chave fora de (obrigatórias ∪ opcionais)."""
    if not isinstance(obj, dict):
        raise ErroValidacao(f"{campo}: objeto esperado")
    chaves = set(obj.keys())
    falta = obrigatorias - chaves
    sobra = chaves - obrigatorias - opcionais
    if falta:
        raise ErroValidacao(f"{campo}: faltam campos {sorted(falta)}")
    if sobra:
        raise ErroValidacao(f"{campo}: campos não permitidos {sorted(sobra)}")
    return obj


# ───────────────────────── arquivos ─────────────────────────


def ler_arquivo_seguro(
    caminho: str,
    max_bytes: int,
    *,
    uid_dono: int | None = None,
    proibir_escrita_outros: bool = False,
    permitir_hardlink: bool = False,
) -> bytes:
    """Lê um arquivo REGULAR, sem seguir symlink, sem travar em FIFO, com limite de tamanho.

    A leitura é um único 'instantâneo' em memória: tudo o que o agente decide depois usa ESTES bytes
    (não relê o arquivo), o que elimina a corrida TOCTOU entre verificar e usar.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(caminho, flags)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise ErroValidacao("link simbólico não é permitido") from e
        raise ErroValidacao(f"não foi possível abrir o arquivo ({e.strerror})") from e
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ErroValidacao("não é arquivo regular")
        if st.st_nlink != 1 and not permitir_hardlink:
            raise ErroValidacao("arquivo com mais de um link físico")
        if st.st_size > max_bytes:
            raise ErroValidacao("arquivo grande demais")
        if uid_dono is not None and st.st_uid != uid_dono:
            raise ErroValidacao("dono inesperado")
        if proibir_escrita_outros and (st.st_mode & 0o022):
            raise ErroValidacao("permissão de escrita para grupo/outros")
        partes = []
        total = 0
        while True:
            pedaco = os.read(fd, 65536)
            if not pedaco:
                break
            total += len(pedaco)
            if total > max_bytes:
                raise ErroValidacao("arquivo cresceu durante a leitura")
            partes.append(pedaco)
        return b"".join(partes)
    finally:
        os.close(fd)


def _fsync_dir(pasta: str) -> None:
    try:
        fd = os.open(pasta, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def escrever_atomico(caminho: str, dados: bytes, modo: int = 0o600) -> None:
    """Grava em arquivo temporário na MESMA pasta, fsync e rename atômico (nunca deixa meio-arquivo)."""
    pasta = os.path.dirname(os.path.abspath(caminho))
    os.makedirs(pasta, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=pasta)
    try:
        try:
            os.fchmod(fd, modo)
            os.write(fd, dados)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, caminho)
        _fsync_dir(pasta)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Trava:
    """Trava exclusiva entre processos (flock). Não bloqueia: se ocupada, levanta Ocupado."""

    def __init__(self, caminho: str):
        self.caminho = caminho
        self._fd: int | None = None

    def __enter__(self) -> "Trava":
        os.makedirs(os.path.dirname(os.path.abspath(self.caminho)), exist_ok=True)
        fd = os.open(self.caminho, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            if e.errno in (errno.EAGAIN, errno.EACCES):
                raise Ocupado("outra execução em andamento") from e
            raise
        self._fd = fd
        return self

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


# ───────────────────────── redação de segredos ─────────────────────────


class Redator:
    """Remove credenciais de QUALQUER texto antes de ele chegar a log, auditoria, estado ou status."""

    PADROES = [
        re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{16,}"),
        re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer|basic)\s+\S+"),
        re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}"),
        re.compile(r"(?i)((?:token|senha|password|passwd|secret|segredo)\s*[=:]\s*)\S+"),
    ]
    MARCA = "[REDIGIDO]"

    _B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")

    def __init__(self) -> None:
        self._literais: set[str] = set()
        self._brutos: set[str] = set()

    def registrar(self, segredo: str | None) -> None:
        if not segredo or len(segredo) < 8:
            return
        self._brutos.add(segredo)
        self._literais.add(segredo)
        # variantes comuns em que o segredo aparece codificado
        self._literais.add(base64.b64encode(segredo.encode()).decode())
        self._literais.add(base64.b64encode(("x-access-token:" + segredo).encode()).decode())

    def limpar(self, texto: Any) -> str:
        t = texto if isinstance(texto, str) else str(texto)
        for lit in sorted(self._literais, key=len, reverse=True):
            t = t.replace(lit, self.MARCA)
        for p in self.PADROES:
            t = p.sub(lambda m: (m.group(1) if m.groups() else "") + self.MARCA, t)
        return self._limpar_base64(t)

    def _limpar_base64(self, t: str) -> str:
        """Qualquer trecho em base64 (padrão ou URL-safe) que, DECODIFICADO, contenha um segredo registrado é redigido por inteiro.
        Cobre o cabeçalho 'Basic base64(usuario:token)' com QUALQUER nome de usuário."""
        if not self._brutos:
            return t

        def troca(m):
            s = m.group(0)
            try:
                dec = base64.b64decode(s.replace("-", "+").replace("_", "/") + "=" * (-len(s.rstrip("=")) % 4)).decode("utf-8", "ignore")
            except (ValueError, TypeError):
                return s
            return self.MARCA if any(seg in dec for seg in self._brutos) else s

        return self._B64.sub(troca, t)

    def limpar_obj(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.limpar(obj)
        if isinstance(obj, dict):
            return {self.limpar(k): self.limpar_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.limpar_obj(v) for v in obj]
        return obj


REDATOR = Redator()


def carregar_token(caminho: str, *, uid_dono: int | None = None) -> str:
    """Lê o token de um arquivo com permissão restrita; registra-o no redator e nunca o devolve em erro."""
    dados = ler_arquivo_seguro(caminho, 4096, uid_dono=uid_dono, proibir_escrita_outros=True)
    if dados and os.path.exists(caminho):
        modo = os.stat(caminho).st_mode & 0o777
        if modo & 0o007:
            raise ErroValidacao("token legível por 'outros': ajuste a permissão (0400/0440)")
    token = dados.decode("utf-8", "replace").strip()
    if not token or "\n" in token or " " in token:
        raise ErroValidacao("arquivo de token inválido")
    REDATOR.registrar(token)
    return token
