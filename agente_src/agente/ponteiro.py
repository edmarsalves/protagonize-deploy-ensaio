"""O 'ponteiro de versão': documento DE DADOS (nunca de comandos) que diz qual versão está autorizada.

Quem o produz é o fluxo do GitHub (já atestado). Aqui ele é tratado como NÃO CONFIÁVEL até passar pelo
esquema estrito e pela verificação de proveniência (ver atestado.py). Nenhum campo vira comando, caminho ou nome de imagem:
só dígitos/hex validados, usados pelo agente para MONTAR nomes a partir da política.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

from .politica import Politica
from .util import (
    ErroValidacao,
    exigir_chaves_exatas,
    exigir_commit,
    exigir_digest,
    exigir_inteiro,
    json_estrito,
    parse_iso_utc,
)

TIPOS = ("release", "reversao")
ESQUEMA = 1
MAX_BYTES = 4096
MAX_BYTES_OCI = 16 * 1024
PREFIXO = "br.protagonize."
CAMPOS_OCI = ("esquema", "seq", "commit", "criado_em", "gatilho", "tipo", "api", "web")
RE_NUM = re.compile(r"\A[1-9][0-9]{0,15}\Z")
RE_ANOT_PADRAO = re.compile(r"\Aorg\.opencontainers\.image\.[a-z.]{1,40}\Z")
RE_MIDIA = re.compile(r"\A[a-z0-9]+/[a-z0-9.+-]{1,80}\Z")
MIDIA_MANIFESTO = "application/vnd.oci.image.manifest.v1+json"


@dataclass(frozen=True)
class Ponteiro:
    seq: int  # = github.run_id da execução que construiu (monotônico)
    commit: str
    criado_em: datetime
    gatilho: str  # push | workflow_dispatch | schedule
    tipo: str  # release | reversao
    api: str | None  # digest sha256:<hex> ou None (serviço não muda neste release)
    web: str | None

    def alvos(self) -> dict:
        return {k: v for k, v in (("api", self.api), ("web", self.web)) if v is not None}


def _descritor(d, campo: str) -> None:
    exigir_chaves_exatas(d, {"mediaType", "digest", "size"}, {"annotations", "artifactType", "data"}, campo)
    if not isinstance(d["mediaType"], str) or not RE_MIDIA.match(d["mediaType"]):
        raise ErroValidacao(f"{campo}.mediaType inválido")
    exigir_digest(d["digest"], f"{campo}.digest")
    exigir_inteiro(d["size"], f"{campo}.size", 0, 10 * 1024 * 1024)


def ponteiro_de_manifesto_oci(obj) -> dict:
    """O ponteiro REAL no GHCR é um MANIFESTO OCI cujas ANOTAÇÕES (br.protagonize.*) carregam os dados. O digest do manifesto é o que recebe o atestado.
    Estrito: chaves exatas; só anotações nossas (+ org.opencontainers.image.* ignoradas); valores TEXTO; seq decimal sem zeros à esquerda."""
    exigir_chaves_exatas(obj, {"schemaVersion", "mediaType", "config", "layers", "annotations"}, {"artifactType"}, "manifesto")
    if obj["schemaVersion"] != 2 or isinstance(obj["schemaVersion"], bool) or obj["mediaType"] != MIDIA_MANIFESTO:
        raise ErroValidacao("manifesto: schemaVersion/mediaType não suportados")
    _descritor(obj["config"], "manifesto.config")
    if not isinstance(obj["layers"], list) or len(obj["layers"]) > 4:
        raise ErroValidacao("manifesto: layers inválidas")
    for i, l in enumerate(obj["layers"]):
        _descritor(l, f"manifesto.layers[{i}]")
    an = obj["annotations"]
    if not isinstance(an, dict) or len(an) > 32:
        raise ErroValidacao("manifesto: annotations inválidas")
    plano = {}
    for k, v in an.items():
        if not isinstance(k, str) or not isinstance(v, str) or len(v) > 200:
            raise ErroValidacao("manifesto: anotação fora do formato (texto esperado)")
        if k.startswith(PREFIXO):
            nome = k[len(PREFIXO):]
            if nome not in CAMPOS_OCI:
                raise ErroValidacao(f"manifesto: anotação desconhecida {k!r}")
            plano[nome] = v
        elif not RE_ANOT_PADRAO.match(k):
            raise ErroValidacao(f"manifesto: anotação não permitida {k!r}")  # só as nossas e as padrão OCI (ignoradas)
    for obrig in ("esquema", "seq", "commit", "criado_em", "gatilho", "tipo"):
        if obrig not in plano:
            raise ErroValidacao(f"manifesto: falta a anotação {PREFIXO}{obrig}")
    for campo in ("esquema", "seq"):
        if not RE_NUM.match(plano[campo]):
            raise ErroValidacao(f"manifesto: {campo} deve ser inteiro decimal sem zeros à esquerda")
        plano[campo] = int(plano[campo])
    return plano


def validar_ponteiro(dados: bytes, politica: Politica, agora: datetime) -> Ponteiro:
    """Valida o ponteiro bruto (manifesto OCI com anotações OU o JSON plano legado). Recusa qualquer campo desconhecido, tipo errado, data fora da janela etc."""
    obj = json_estrito(dados, MAX_BYTES_OCI)
    if isinstance(obj, dict) and "schemaVersion" in obj:
        obj = ponteiro_de_manifesto_oci(obj)
    elif len(dados) > MAX_BYTES:
        raise ErroValidacao("ponteiro: grande demais")
    exigir_chaves_exatas(
        obj,
        obrigatorias={"esquema", "seq", "commit", "criado_em", "gatilho", "tipo"},
        opcionais={"api", "web"},
        campo="ponteiro",
    )
    if obj["esquema"] != ESQUEMA or isinstance(obj["esquema"], bool):
        raise ErroValidacao("ponteiro: esquema não suportado")
    seq = exigir_inteiro(obj["seq"], "ponteiro.seq")
    commit = exigir_commit(obj["commit"], "ponteiro.commit")
    criado = parse_iso_utc(obj["criado_em"], "ponteiro.criado_em")
    if obj["gatilho"] not in politica.eventos:
        raise ErroValidacao("ponteiro: gatilho não permitido pela política")
    if obj["tipo"] not in TIPOS:
        raise ErroValidacao("ponteiro: tipo inválido")
    api = exigir_digest(obj["api"], "ponteiro.api") if "api" in obj else None
    web = exigir_digest(obj["web"], "ponteiro.web") if "web" in obj else None
    if api is None and web is None:
        raise ErroValidacao("ponteiro: nenhum serviço informado")
    if (api is not None and "api" not in politica.servicos) or (web is not None and "web" not in politica.servicos):
        raise ErroValidacao("ponteiro: serviço não permitido pela política")
    if criado > agora + politica.tolerancia():
        raise ErroValidacao("ponteiro: data no futuro")
    if agora - criado > politica.validade_ponteiro():
        raise ErroValidacao("ponteiro: expirado (validade excedida)")
    return Ponteiro(seq=seq, commit=commit, criado_em=criado, gatilho=obj["gatilho"], tipo=obj["tipo"], api=api, web=web)
