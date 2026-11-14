"""Cliente do registro de imagens (GHCR). Só LÊ (token de leitura). Todas as falhas de comunicação viram ErroComunicacao.

Regras: HTTPS obrigatório (exceto loopback nos testes), redirecionamentos só para hosts da lista, limite de tamanho por resposta,
tempo limite, TLS sempre verificado (sem opção de desligar), token nunca em URL/log. Falha de rede NUNCA vira "tentar assim mesmo".

LIMITAÇÃO (a validar no Lote 3/4 contra o GHCR real): o mapeamento exato de ponteiro→manifesto/anotações e de atestado→bundle
(tags `sha256-<hex>.att` vs API de referrers) é definido aqui por convenção e testado contra um servidor FALSO equivalente.
"""
from __future__ import annotations

import base64
import http.client
import json
import random
import socket
import ssl
import time
import urllib.parse
from abc import ABC, abstractmethod

from .util import REDATOR, ErroComunicacao, ErroValidacao, RE_DIGEST

HOSTS_PADRAO = ("ghcr.io", "pkg-containers.githubusercontent.com")
TIPO_BUNDLE = "application/vnd.dev.sigstore.bundle.v0.3+json"
TIPO_PREDICADO_SLSA = "https://slsa.dev/provenance/v1"
MAX_REFERRERS = 20


class ClienteRegistro(ABC):
    @abstractmethod
    def digest_do_ponteiro(self, nome_release: str, tag: str) -> str | None: ...
    @abstractmethod
    def baixar_ponteiro(self, nome_release: str, digest: str) -> bytes: ...
    @abstractmethod
    def baixar_atestado(self, nome: str, digest: str) -> bytes: ...


class Backoff:
    """Espera crescente com teto e jitter. O sorteador é injetável (testes determinísticos)."""

    def __init__(self, base_s: float = 60.0, teto_s: float = 1800.0, rng=None):
        self.base, self.teto = base_s, teto_s
        self.rng = rng or random.Random()

    def espera(self, falhas_seguidas: int, retry_apos: float | None = None) -> float:
        if falhas_seguidas <= 0:
            return 0.0
        e = min(self.teto, self.base * (2 ** (falhas_seguidas - 1)))
        e = e * (0.75 + 0.5 * self.rng.random())
        return min(self.teto, max(e, retry_apos or 0.0))


class ClienteGHCR(ClienteRegistro):
    def __init__(self, base_url: str, usuario: str, token_fn, *, hosts_permitidos=HOSTS_PADRAO, tempo_limite: float = 20.0,
                 permitir_http_loopback: bool = False, max_bytes: int = 600 * 1024, contexto_tls: ssl.SSLContext | None = None):
        u = urllib.parse.urlsplit(base_url)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise ErroValidacao("base_url inválida")
        if u.scheme == "http" and not (permitir_http_loopback and u.hostname in ("127.0.0.1", "localhost", "::1")):
            raise ErroValidacao("HTTP só é aceito em loopback de teste")
        self.u, self.usuario, self.token_fn = u, usuario, token_fn
        self.hosts = set(hosts_permitidos) | {u.hostname}
        self.tempo, self.max_bytes = tempo_limite, max_bytes
        self.ctx = contexto_tls or ssl.create_default_context()  # verificação de certificado e de nome SEMPRE ligada
        self._bearer: dict = {}

    # ─── HTTP baixo nível ───
    def _conexao(self, host: str, porta: int | None, https: bool):
        if https:
            return http.client.HTTPSConnection(host, porta, timeout=self.tempo, context=self.ctx)
        return http.client.HTTPConnection(host, porta, timeout=self.tempo)

    def _pedir(self, metodo: str, url: str, cabecalhos: dict, *, redirecionamentos: int = 3):
        p = urllib.parse.urlsplit(url)
        if p.hostname not in self.hosts:
            raise ErroComunicacao("host fora da lista permitida", transitorio=False)
        if p.scheme == "http" and p.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ErroComunicacao("HTTP não permitido", transitorio=False)
        c = None
        try:
            c = self._conexao(p.hostname, p.port, p.scheme == "https")
            caminho = p.path + ("?" + p.query if p.query else "")
            c.request(metodo, caminho or "/", headers=cabecalhos)
            r = c.getresponse()
            corpo = b""
            if metodo != "HEAD":
                corpo = r.read(self.max_bytes + 1)
                if len(corpo) > self.max_bytes:
                    raise ErroComunicacao("resposta grande demais", transitorio=False)
            status, hdrs = r.status, {k.lower(): v for k, v in r.getheaders()}
        except ErroComunicacao:
            raise
        except (socket.timeout, TimeoutError) as e:
            raise ErroComunicacao("tempo esgotado") from e
        except ssl.SSLError as e:
            raise ErroComunicacao("falha de TLS/certificado (fail-closed)") from e
        except (OSError, http.client.HTTPException) as e:
            raise ErroComunicacao("falha de rede: " + REDATOR.limpar(type(e).__name__)) from e
        finally:
            if c is not None:
                c.close()  # sempre fecha a conexão, inclusive nos caminhos de erro
        if status in (301, 302, 303, 307, 308):
            if redirecionamentos <= 0 or "location" not in hdrs:
                raise ErroComunicacao("redirecionamentos demais", transitorio=False)
            destino = urllib.parse.urljoin(url, hdrs["location"])
            # NUNCA reenvia o cabeçalho de autorização para outro host
            h2 = {k: v for k, v in cabecalhos.items() if k.lower() != "authorization"} if urllib.parse.urlsplit(destino).hostname != p.hostname else cabecalhos
            return self._pedir(metodo, destino, h2, redirecionamentos=redirecionamentos - 1)
        return status, hdrs, corpo

    def _verificar_status(self, status: int, hdrs: dict, o_que: str):
        if status == 429:
            ra = hdrs.get("retry-after", "")
            raise ErroComunicacao(f"limite de taxa em {o_que}", transitorio=True, retry_apos=float(ra) if ra.isdigit() else None)
        if status >= 500:
            raise ErroComunicacao(f"erro do servidor ({status}) em {o_que}")
        if status in (401, 403):
            raise ErroComunicacao(f"acesso negado ({status}) em {o_que}: token inválido/expirado/sem permissão", transitorio=False)
        if status != 200:
            raise ErroComunicacao(f"resposta inesperada ({status}) em {o_que}", transitorio=False)

    def _bearer_para(self, nome: str) -> str:
        if nome in self._bearer:
            return self._bearer[nome]
        token = self.token_fn()
        basico = base64.b64encode(f"{self.usuario}:{token}".encode()).decode()
        url = f"{self.u.scheme}://{self.u.netloc}/token?service={self.u.hostname}&scope=repository:{urllib.parse.quote(nome, safe='/')}:pull"
        status, hdrs, corpo = self._pedir("GET", url, {"Authorization": "Basic " + basico})
        self._verificar_status(status, hdrs, "troca de token")
        try:
            tk = json.loads(corpo.decode("utf-8"))["token"]
        except (ValueError, KeyError, UnicodeDecodeError) as e:
            raise ErroComunicacao("resposta de token ilegível", transitorio=False) from e
        if not isinstance(tk, str) or not tk:
            raise ErroComunicacao("token vazio", transitorio=False)
        REDATOR.registrar(tk)
        self._bearer[nome] = tk
        return tk

    def _get(self, metodo: str, nome: str, ref: str, aceitar: str):
        if "/" not in nome or ".." in nome or not all(c.isalnum() or c in "/._-" for c in nome):
            raise ErroValidacao("nome de repositório inválido")
        if not all(c.isalnum() or c in ".:_-" for c in ref):
            raise ErroValidacao("referência inválida")
        url = f"{self.u.scheme}://{self.u.netloc}/v2/{nome}/manifests/{ref}"
        try:
            return self._pedir(metodo, url, {"Authorization": "Bearer " + self._bearer_para(nome), "Accept": aceitar})
        except ErroComunicacao:
            self._bearer.pop(nome, None)  # token pode ter expirado: renova na próxima
            raise

    # ─── API do agente ───
    def digest_do_ponteiro(self, nome_release: str, tag: str) -> str | None:
        status, hdrs, _ = self._get("HEAD", nome_release, tag, "application/vnd.oci.image.manifest.v1+json")
        if status == 404:
            return None
        self._verificar_status(status, hdrs, "ponteiro")
        d = hdrs.get("docker-content-digest", "")
        if not RE_DIGEST.match(d):
            raise ErroComunicacao("digest do ponteiro ausente/inválido", transitorio=False)
        return d

    def baixar_ponteiro(self, nome_release: str, digest: str) -> bytes:
        status, hdrs, corpo = self._get("GET", nome_release, digest, "application/vnd.oci.image.manifest.v1+json")
        self._verificar_status(status, hdrs, "manifesto do ponteiro")
        return corpo

    def _obter(self, nome: str, caminho: str, aceitar: str):
        """GET autenticado em /v2/<nome>/<caminho> (referrers, manifestos e blobs)."""
        if "/" not in nome or ".." in nome or not all(c.isalnum() or c in "/._-" for c in nome):
            raise ErroValidacao("nome de repositório inválido")
        url = f"{self.u.scheme}://{self.u.netloc}/v2/{nome}/{caminho}"
        try:
            return self._pedir("GET", url, {"Authorization": "Bearer " + self._bearer_para(nome), "Accept": aceitar})
        except ErroComunicacao:
            self._bearer.pop(nome, None)
            raise

    def baixar_atestado(self, nome: str, digest: str) -> bytes:
        """Atestado de proveniência guardado NO REGISTRO como artefato OCI (API de referrers do OCI 1.1):
        índice de referrers → manifesto do bundle → blob do bundle (digest do blob CONFERIDO). Devolve b'' se não houver.
        LIMITAÇÃO: o formato exato que o GHCR usa para `push-to-registry` só pode ser comprovado com um repositório real (ver docs)."""
        if not RE_DIGEST.match(digest):
            raise ErroValidacao("digest inválido")
        import hashlib
        from urllib.parse import quote
        status, hdrs, corpo = self._obter(nome, f"referrers/{digest}?artifactType={quote(TIPO_BUNDLE, safe='')}", "application/vnd.oci.image.index.v1+json")
        if status == 404:
            return b""
        self._verificar_status(status, hdrs, "referrers")
        try:
            indice = json.loads(corpo.decode("utf-8"))
            candidatos = [m for m in (indice.get("manifests") or [])[:MAX_REFERRERS]
                          if isinstance(m, dict) and m.get("artifactType") == TIPO_BUNDLE and RE_DIGEST.match(str(m.get("digest", "")))
                          and (m.get("annotations") or {}).get("dev.sigstore.bundle.predicateType", TIPO_PREDICADO_SLSA) == TIPO_PREDICADO_SLSA]
        except (ValueError, UnicodeDecodeError, AttributeError) as e:
            raise ErroComunicacao("índice de referrers ilegível", transitorio=False) from e
        if not candidatos:
            return b""
        escolhido = sorted(candidatos, key=lambda m: m["digest"])[0]  # determinístico; se houver vários, o verificador criptográfico decide (limitação documentada)
        st, h, mbruto = self._obter(nome, f"manifests/{escolhido['digest']}", "application/vnd.oci.image.manifest.v1+json")
        self._verificar_status(st, h, "manifesto do atestado")
        try:
            man = json.loads(mbruto.decode("utf-8"))
            camadas = man["layers"]
            if not isinstance(camadas, list) or len(camadas) != 1:
                raise ValueError("o bundle deve ter exatamente 1 camada")
            blob_digest, tam = str(camadas[0]["digest"]), int(camadas[0]["size"])
            if not RE_DIGEST.match(blob_digest) or not (0 < tam <= self.max_bytes):
                raise ValueError("camada fora do formato/limite")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
            raise ErroComunicacao("manifesto do atestado inválido: " + REDATOR.limpar(e), transitorio=False) from e
        st, h, blob = self._obter(nome, f"blobs/{blob_digest}", "application/octet-stream")
        self._verificar_status(st, h, "blob do atestado")
        if "sha256:" + hashlib.sha256(blob).hexdigest() != blob_digest:
            raise ErroComunicacao("o blob do atestado NÃO corresponde ao digest do manifesto", transitorio=False)
        return blob
