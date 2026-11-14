"""VERIFICADOR (usuário SEM privilégio; sem acesso ao Docker). Único componente que fala com GitHub/GHCR.

Consulta o ponteiro de versão, faz a verificação preliminar (falha rápida) e entrega um PACOTE ao executor. NÃO decide publicar
e NÃO tem poder de publicar: o executor refaz tudo. Comprometer este componente não permite publicar versão não atestada.
Falhas de comunicação: não faz nada, espera com backoff crescente e nunca "tenta assim mesmo".
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import timedelta

from . import canal
from .atestado import BackendAtestado, EsperadoCertificado, verificar_pacote
from .estado import Auditoria
from .politica import Politica
from .ponteiro import validar_ponteiro
from .registro import Backoff, ClienteRegistro
from .util import (
    REDATOR,
    AtestadoInvalido,
    ErroComunicacao,
    ErroValidacao,
    ProvenienciaRejeitada,
    agora_utc,
    digest_de,
    escrever_atomico,
    iso_utc,
    json_estrito,
    ler_arquivo_seguro,
    parse_iso_utc,
)

TERMINAIS = ("ok", "sem_mudanca", "revertido", "recusado", "falhou_critico")


@dataclass
class ConfigVerificador:
    entrada: str
    estado_path: str
    status_path: str  # leitura do status público (para saber se o executor já concluiu)
    reentrega_s: int = 180


class Verificador:
    def __init__(self, politica: Politica, cfg: ConfigVerificador, cliente: ClienteRegistro, backend: BackendAtestado, auditoria: Auditoria,
                 backoff: Backoff | None = None, relogio=agora_utc):
        self.politica, self.cfg, self.cliente, self.backend, self.aud = politica, cfg, cliente, backend, auditoria
        self.backoff = backoff or Backoff()
        self.relogio = relogio

    # estado próprio (pequeno; sem segredos)
    def _ler(self) -> dict:
        base = {"entregue": {}, "rejeitados": [], "falhas": 0, "proxima": None}
        if not os.path.exists(self.cfg.estado_path):
            return base
        try:
            obj = json_estrito(ler_arquivo_seguro(self.cfg.estado_path, 64 * 1024), 64 * 1024)
            if not isinstance(obj, dict) or set(obj) != set(base):
                raise ErroValidacao("estado do verificador inválido")
            return obj
        except ErroValidacao:
            return base  # estado do verificador é descartável: o executor é quem guarda o que importa

    def _gravar(self, e: dict) -> None:
        e["rejeitados"] = e["rejeitados"][-100:]
        e["entregue"] = dict(sorted(e["entregue"].items(), key=lambda kv: kv[1])[-50:])
        escrever_atomico(self.cfg.estado_path, json.dumps(e, sort_keys=True).encode(), 0o600)

    def _status_do_ponteiro(self, digest: str) -> str | None:
        try:
            obj = json_estrito(ler_arquivo_seguro(self.cfg.status_path, 8192), 8192)
        except (ErroValidacao, OSError):
            return None
        return obj.get("status") if isinstance(obj, dict) and obj.get("ponteiro") == digest else None

    def ciclo(self) -> str:
        agora = self.relogio()
        e = self._ler()
        if e["proxima"] and agora < parse_iso_utc(e["proxima"]):
            return "AGUARDANDO_BACKOFF"
        try:
            return self._ciclo(e, agora)
        except ErroComunicacao as ex:
            e["falhas"] += 1
            espera = self.backoff.espera(e["falhas"], ex.retry_apos)
            e["proxima"] = iso_utc(agora + timedelta(seconds=espera))
            self._gravar(e)
            self.aud.registrar("comunicacao_falhou", falhas=e["falhas"], transitorio=ex.transitorio, espera_s=int(espera), motivo=REDATOR.limpar(ex))
            return "ADIADO_COMUNICACAO"

    def _ciclo(self, e: dict, agora) -> str:
        p = self.politica
        digest = self.cliente.digest_do_ponteiro(p.nome_imagem("release").split("/", 1)[1], p.tag_ponteiro)
        e["falhas"], e["proxima"] = 0, None
        if digest is None or digest in e["rejeitados"]:
            self._gravar(e)
            return "SEM_NOVIDADE"
        if digest in e["entregue"]:
            st = self._status_do_ponteiro(digest)
            ha = (agora - parse_iso_utc(e["entregue"][digest])).total_seconds()
            if st in TERMINAIS or ha < self.cfg.reentrega_s:
                self._gravar(e)
                return "JA_PROCESSADO" if st in TERMINAIS else "AGUARDANDO_EXECUTOR"
            # entregue, mas o executor não concluiu (ex.: 'adiado' ou pacote perdido): reentrega o MESMO ponteiro
        return self._verificar_e_entregar(e, digest, agora)

    def _verificar_e_entregar(self, e: dict, digest: str, agora) -> str:
        p = self.politica
        repo_release = p.nome_imagem("release").split("/", 1)[1]
        try:
            bruto = self.cliente.baixar_ponteiro(repo_release, digest)
            if digest_de(bruto) != digest:
                raise AtestadoInvalido("o ponteiro baixado NÃO corresponde ao digest anunciado (adulterado/substituído)")
            pt = validar_ponteiro(bruto, p, agora)
            arquivos = {"ponteiro.json": bruto, "ponteiro.atestado.json": self.cliente.baixar_atestado(repo_release, digest)}
            for svc, dig in pt.alvos().items():
                arquivos[f"{svc}.atestado.json"] = self.cliente.baixar_atestado(p.nome_imagem(svc).split("/", 1)[1], dig)
            verificar_pacote(arquivos, p, self.backend, agora)  # verificação preliminar (o executor repete)
        except (ErroValidacao, AtestadoInvalido, ProvenienciaRejeitada) as ex:
            e["rejeitados"].append(digest)
            self._gravar(e)
            self.aud.registrar("ponteiro_rejeitado", ponteiro=digest, codigo=getattr(ex, "codigo", type(ex).__name__), motivo=REDATOR.limpar(ex))
            return "REJEITADO"
        arquivos["meta.json"] = json.dumps({"criado_em": iso_utc(agora), "versao_pacote": 1}).encode()
        canal.entregar_pacote(self.cfg.entrada, pt.seq, arquivos)
        e["entregue"][digest] = iso_utc(agora)
        self._gravar(e)
        self.aud.registrar("pacote_entregue", seq=pt.seq, ponteiro=digest)
        return "ENTREGUE"
