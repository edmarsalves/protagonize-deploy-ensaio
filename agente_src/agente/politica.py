"""Política de autorização: QUEM pode publicar o quê. Vem de um arquivo LOCAL da VPS (root), nunca do repositório.

Nada aqui é lido do GitHub. Se a política estiver errada ou adulterada, o agente não sobe (fail-closed).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from .util import (
    ErroValidacao,
    RE_ID_NUMERICO,
    exigir_chaves_exatas,
    exigir_inteiro,
    json_estrito,
    ler_arquivo_seguro,
)

EVENTOS_CONHECIDOS = ("push", "workflow_dispatch", "schedule")
SERVICOS_CONHECIDOS = ("api", "web")
RE_REGISTRO = re.compile(r"\A[a-z0-9.-]{3,64}\Z")
RE_NAMESPACE = re.compile(r"\A[a-z0-9][a-z0-9-]{0,38}\Z")
RE_IMAGEM = re.compile(r"\A[a-z0-9][a-z0-9._-]{0,63}\Z")
RE_REPO = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}\Z")
RE_WORKFLOW = re.compile(r"\A\.github/workflows/[A-Za-z0-9._-]{1,80}\.ya?ml\Z")
RE_REF = re.compile(r"\Arefs/heads/[A-Za-z0-9._/-]{1,100}\Z")
RE_URL_EMISSOR = re.compile(r"\Ahttps://[a-z0-9.-]+(/[A-Za-z0-9._/-]*)?\Z")
RE_TAG = re.compile(r"\A[A-Za-z0-9._-]{1,64}\Z")


@dataclass(frozen=True)
class Politica:
    registro: str
    namespace: str
    imagens: dict  # papel -> nome do repositório da imagem ("api", "web", "release")
    repositorio: str  # "dono/repo" do GitHub
    repositorio_id: str
    dono_id: str
    workflow: str
    ref: str
    emissor: str
    eventos: tuple
    exigir_runner_hospedado: bool
    validade_ponteiro_s: int
    tolerancia_relogio_s: int
    max_tentativas: int
    servicos: tuple
    tag_ponteiro: str

    @property
    def san_esperado(self) -> str:
        """Identidade do certificado Sigstore esperada (URL do workflow na ref autorizada)."""
        return f"https://github.com/{self.repositorio}/{self.workflow}@{self.ref}"

    @property
    def url_repositorio(self) -> str:
        return f"https://github.com/{self.repositorio}"

    def nome_imagem(self, papel: str) -> str:
        """Nome COMPLETO (sem digest) de uma imagem autorizada. Único construtor de nomes do agente."""
        if papel not in self.imagens:
            raise ErroValidacao(f"imagem fora da lista autorizada: {papel!r}")
        return f"{self.registro}/{self.namespace}/{self.imagens[papel]}"

    def validade_ponteiro(self) -> timedelta:
        return timedelta(seconds=self.validade_ponteiro_s)

    def tolerancia(self) -> timedelta:
        return timedelta(seconds=self.tolerancia_relogio_s)


def validar_politica(obj) -> Politica:
    obrig = {
        "registro", "namespace", "imagens", "repositorio", "repositorio_id", "dono_id", "workflow", "ref",
        "emissor", "eventos", "exigir_runner_hospedado", "validade_ponteiro_s", "tolerancia_relogio_s",
        "max_tentativas", "servicos", "tag_ponteiro",
    }
    exigir_chaves_exatas(obj, obrig, set(), "politica")
    if not isinstance(obj["registro"], str) or not RE_REGISTRO.match(obj["registro"]):
        raise ErroValidacao("politica.registro inválido")
    if not isinstance(obj["namespace"], str) or not RE_NAMESPACE.match(obj["namespace"]):
        raise ErroValidacao("politica.namespace inválido")
    imagens = exigir_chaves_exatas(obj["imagens"], {"api", "web", "release"}, set(), "politica.imagens")
    for papel, nome in imagens.items():
        if not isinstance(nome, str) or not RE_IMAGEM.match(nome):
            raise ErroValidacao(f"politica.imagens.{papel} inválido")
    if len(set(imagens.values())) != 3:
        raise ErroValidacao("politica.imagens: nomes devem ser distintos")
    if not isinstance(obj["repositorio"], str) or not RE_REPO.match(obj["repositorio"]):
        raise ErroValidacao("politica.repositorio inválido")
    for campo in ("repositorio_id", "dono_id"):
        if not isinstance(obj[campo], str) or not RE_ID_NUMERICO.match(obj[campo]):
            raise ErroValidacao(f"politica.{campo}: ID numérico imutável (texto) esperado")
    if not isinstance(obj["workflow"], str) or not RE_WORKFLOW.match(obj["workflow"]):
        raise ErroValidacao("politica.workflow inválido")
    if not isinstance(obj["ref"], str) or not RE_REF.match(obj["ref"]) or ".." in obj["ref"]:
        raise ErroValidacao("politica.ref inválida (use refs/heads/<branch>)")
    if not isinstance(obj["emissor"], str) or not RE_URL_EMISSOR.match(obj["emissor"]):
        raise ErroValidacao("politica.emissor inválido")
    eventos = obj["eventos"]
    if not isinstance(eventos, list) or not eventos or any(e not in EVENTOS_CONHECIDOS for e in eventos) or len(set(eventos)) != len(eventos):
        raise ErroValidacao(f"politica.eventos deve ser subconjunto não vazio de {EVENTOS_CONHECIDOS}")
    if not isinstance(obj["exigir_runner_hospedado"], bool):
        raise ErroValidacao("politica.exigir_runner_hospedado: booleano")
    validade = exigir_inteiro(obj["validade_ponteiro_s"], "politica.validade_ponteiro_s", 60, 30 * 86400)
    tol = exigir_inteiro(obj["tolerancia_relogio_s"], "politica.tolerancia_relogio_s", 0, 3600)
    tentativas = exigir_inteiro(obj["max_tentativas"], "politica.max_tentativas", 1, 10)
    servicos = obj["servicos"]
    if not isinstance(servicos, list) or not servicos or any(s not in SERVICOS_CONHECIDOS for s in servicos) or len(set(servicos)) != len(servicos):
        raise ErroValidacao(f"politica.servicos deve ser subconjunto não vazio de {SERVICOS_CONHECIDOS}")
    if not isinstance(obj["tag_ponteiro"], str) or not RE_TAG.match(obj["tag_ponteiro"]):
        raise ErroValidacao("politica.tag_ponteiro inválida")
    return Politica(
        registro=obj["registro"], namespace=obj["namespace"], imagens=dict(imagens), repositorio=obj["repositorio"],
        repositorio_id=obj["repositorio_id"], dono_id=obj["dono_id"], workflow=obj["workflow"], ref=obj["ref"],
        emissor=obj["emissor"], eventos=tuple(eventos), exigir_runner_hospedado=obj["exigir_runner_hospedado"],
        validade_ponteiro_s=validade, tolerancia_relogio_s=tol, max_tentativas=tentativas,
        servicos=tuple(servicos), tag_ponteiro=obj["tag_ponteiro"],
    )


def carregar_politica(caminho: str, *, uid_dono: int | None = None) -> Politica:
    """Lê a política com checagens de dono/permissão (na VPS: root, 0440; nunca gravável por grupo/outros)."""
    dados = ler_arquivo_seguro(caminho, 16 * 1024, uid_dono=uid_dono, proibir_escrita_outros=True)
    return validar_politica(json_estrito(dados, 16 * 1024))
