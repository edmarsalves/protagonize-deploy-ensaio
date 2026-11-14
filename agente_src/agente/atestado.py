"""Verificação de ORIGEM e AUTORIZAÇÃO de uma versão.

Duas camadas, de propósito:
  1) BackendAtestado  — verifica a ASSINATURA (Sigstore/cosign em produção; raiz simulada nos testes).
                       Responde: "este atestado é autêntico e cobre ESTE digest?".
  2) validar_proveniencia — decide se o atestado AUTORIZA: repositório (nome e IDs imutáveis), workflow, ref,
                       evento, runner, COMMIT e EXECUÇÃO (run_id) precisam bater com a política e com o ponteiro.
Um atestado autêntico de outro repositório, outro workflow, outra branch ou outra execução é RECUSADO.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime

from .politica import Politica
from .ponteiro import Ponteiro, validar_ponteiro
from .util import (
    AtestadoInvalido,
    ErroValidacao,
    ProvenienciaRejeitada,
    digest_de,
    json_estrito,
)

TIPO_STATEMENT = "https://in-toto.io/Statement/v1"
TIPO_PREDICADO = "https://slsa.dev/provenance/v1"
NOMES_PACOTE = ("ponteiro.json", "ponteiro.atestado.json", "api.atestado.json", "web.atestado.json", "meta.json")
MAX_ATESTADO = 512 * 1024


@dataclass(frozen=True)
class EsperadoCertificado:
    """O que o PONTEIRO afirma e que o certificado/atestado precisa CONFIRMAR (não o contrário)."""
    commit: str
    gatilho: str


@dataclass(frozen=True)
class Reivindicacoes:
    """Campos do certificado de identidade (Sigstore/Fulcio) já verificados pelo backend."""
    emissor: str
    san: str
    repositorio: str  # "dono/repo"
    ref: str
    sha: str
    evento: str


@dataclass(frozen=True)
class AtestadoVerificado:
    reivindicacoes: Reivindicacoes
    declaracao: dict  # in-toto Statement (somente DEPOIS da assinatura verificada)


class BackendAtestado(ABC):
    @abstractmethod
    def verificar(self, atestado: bytes, digest_sujeito: str, esperado: EsperadoCertificado) -> AtestadoVerificado:
        """Levanta AtestadoInvalido se ausente/adulterado/não cobre o digest. Não decide autorização."""


def _rejeitar(codigo: str, mensagem: str):
    e = ProvenienciaRejeitada(mensagem)
    e.codigo = codigo  # type: ignore[attr-defined]
    raise e


def _caminho(obj, *chaves):
    atual = obj
    for k in chaves:
        if not isinstance(atual, dict) or k not in atual:
            _rejeitar("declaracao_incompleta", f"declaração sem o campo {'.'.join(chaves)}")
        atual = atual[k]
    return atual


def validar_proveniencia(
    av: AtestadoVerificado,
    politica: Politica,
    *,
    papel: str,
    digest_sujeito: str,
    commit: str,
    seq: int,
    gatilho: str,
) -> int:
    """Decide se o atestado AUTORIZA publicar este artefato. Devolve o nº da tentativa da execução."""
    d = av.declaracao
    if not isinstance(d, dict):
        _rejeitar("declaracao_invalida", "declaração não é objeto")
    if d.get("_type") != TIPO_STATEMENT or d.get("predicateType") != TIPO_PREDICADO:
        _rejeitar("tipo_predicado", "tipo de declaração/predicado não suportado")

    # 1) o atestado é sobre ESTE artefato (nome autorizado + digest exato; um único sujeito)
    sujeitos = d.get("subject")
    if not isinstance(sujeitos, list) or not sujeitos or not all(isinstance(x, dict) for x in sujeitos):
        _rejeitar("sujeito", "o atestado deve listar sujeitos")
    nome_esperado = politica.nome_imagem(papel)
    # um atestado real pode cobrir VÁRIOS artefatos; o que autoriza é existir EXATAMENTE UM sujeito com o nome autorizado,
    # e ele precisa ter o digest exato desta versão (nome duplicado com digests diferentes = ambíguo = recusa)
    com_nome = [x for x in sujeitos if x.get("name") == nome_esperado]
    if len(com_nome) != 1:
        _rejeitar("imagem_nao_autorizada", "o atestado não tem exatamente um sujeito com o nome da imagem autorizada")
    dig = com_nome[0].get("digest")
    if not isinstance(dig, dict) or "sha256" not in dig or "sha256:" + str(dig["sha256"]) != digest_sujeito:
        _rejeitar("digest_diferente", "o digest do atestado difere do digest da versão")

    # 2) identidade do certificado (quem assinou)
    r = av.reivindicacoes
    if r.emissor != politica.emissor:
        _rejeitar("emissor", "emissor OIDC não permitido")
    # ordem importa só para o DIAGNÓSTICO (a SAN embute repositório+workflow+ref): do mais específico ao mais geral
    if r.repositorio != politica.repositorio:
        _rejeitar("repositorio_nao_permitido", "repositório do certificado não é o autorizado")
    if r.ref != politica.ref:
        _rejeitar("branch_nao_permitida", "ref do certificado não é a autorizada")
    if r.san != politica.san_esperado:
        _rejeitar("workflow_nao_permitido", "identidade (workflow/ref) do certificado não é a autorizada")
    if r.evento not in politica.eventos or r.evento != gatilho:
        _rejeitar("evento", "evento do certificado não confere com o ponteiro/política")
    if r.sha != commit:
        _rejeitar("commit_diferente", "commit do certificado difere do ponteiro")

    # 3) o que o atestado DIZ que foi construído (conteúdo assinado)
    wf = _caminho(d, "predicate", "buildDefinition", "externalParameters", "workflow")
    if wf.get("repository") != politica.url_repositorio or wf.get("ref") != politica.ref or wf.get("path") != politica.workflow:
        _rejeitar("workflow_nao_permitido", "repositório/ref/workflow do predicado não são os autorizados")
    gh = _caminho(d, "predicate", "buildDefinition", "internalParameters", "github")
    if str(gh.get("repository_id")) != politica.repositorio_id or str(gh.get("repository_owner_id")) != politica.dono_id:
        _rejeitar("repositorio_nao_permitido", "IDs imutáveis de repositório/dono não conferem (renomeação/sequestro de repo)")
    if gh.get("event_name") != gatilho:
        _rejeitar("evento", "evento do predicado difere do ponteiro")
    if politica.exigir_runner_hospedado and gh.get("runner_environment") != "github-hosted":
        _rejeitar("runner_nao_permitido", "build fora do runner hospedado do GitHub")
    deps = _caminho(d, "predicate", "buildDefinition", "resolvedDependencies")
    if not isinstance(deps, list) or len(deps) != 1 or not isinstance(deps[0], dict):
        _rejeitar("dependencias", "resolvedDependencies deve ter exatamente 1 item")
    if deps[0].get("uri") != f"git+{politica.url_repositorio}@{politica.ref}":
        _rejeitar("branch_nao_permitida", "origem do código (uri) não é a autorizada")
    if _caminho(deps[0], "digest").get("gitCommit") != commit:
        _rejeitar("commit_diferente", "commit do predicado difere do ponteiro")

    # 4) a EXECUÇÃO: o run_id do atestado tem de ser o 'seq' do ponteiro
    inv = _caminho(d, "predicate", "runDetails", "metadata", "invocationId")
    m = re.match(r"\A" + re.escape(politica.url_repositorio) + r"/actions/runs/([0-9]{1,20})/attempts/([0-9]{1,6})\Z", inv if isinstance(inv, str) else "")
    if not m:
        _rejeitar("execucao", "invocationId fora do formato esperado")
    if int(m.group(1)) != seq:
        _rejeitar("execucao_diferente", "o atestado é de OUTRA execução (run_id ≠ seq do ponteiro)")
    return int(m.group(2))


@dataclass(frozen=True)
class VersaoAutorizada:
    seq: int
    commit: str
    gatilho: str
    tipo: str
    digest_ponteiro: str
    criado_em: datetime
    alvos: dict  # {"api": "sha256:…", "web": "sha256:…"} (somente o que muda)


def verificar_pacote(pacote: dict, politica: Politica, backend: BackendAtestado, agora: datetime) -> VersaoAutorizada:
    """Verificação completa e INDEPENDENTE de um pacote (usada pelo verificador E, de novo, pelo executor).

    'pacote' é um instantâneo em memória {nome: bytes}: o que foi verificado é exatamente o que será usado.
    """
    if "ponteiro.json" not in pacote or "ponteiro.atestado.json" not in pacote:
        raise AtestadoInvalido("pacote sem ponteiro ou sem atestado do ponteiro")
    ponteiro_bytes = pacote["ponteiro.json"]
    pt: Ponteiro = validar_ponteiro(ponteiro_bytes, politica, agora)
    digest_ponteiro = digest_de(ponteiro_bytes)

    esperado = EsperadoCertificado(commit=pt.commit, gatilho=pt.gatilho)
    av = backend.verificar(pacote["ponteiro.atestado.json"], digest_ponteiro, esperado)
    validar_proveniencia(av, politica, papel="release", digest_sujeito=digest_ponteiro, commit=pt.commit, seq=pt.seq, gatilho=pt.gatilho)

    for servico, digest in pt.alvos().items():
        nome = f"{servico}.atestado.json"
        if nome not in pacote:
            raise AtestadoInvalido(f"atestado de {servico} ausente")
        av_s = backend.verificar(pacote[nome], digest, esperado)
        validar_proveniencia(av_s, politica, papel=servico, digest_sujeito=digest, commit=pt.commit, seq=pt.seq, gatilho=pt.gatilho)
    # atestados de serviços que o ponteiro NÃO lista são ignorados e nunca usados (mas o canal já recusa arquivos extras)
    return VersaoAutorizada(
        seq=pt.seq, commit=pt.commit, gatilho=pt.gatilho, tipo=pt.tipo, digest_ponteiro=digest_ponteiro,
        criado_em=pt.criado_em, alvos=pt.alvos(),
    )


class BackendCosign(BackendAtestado):
    """Backend de PRODUÇÃO: chama o `cosign` (argumentos fixos, sem shell, ambiente mínimo, offline com o bundle).

    ATENÇÃO (limitação conhecida, a validar no Lote 3/4 contra um atestado REAL do GitHub): os NOMES exatos das opções do
    cosign e o formato do 'bundle' dependem da versão. Aqui os campos do certificado são exigidos como OPÇÕES do cosign
    (ele só devolve sucesso se a identidade bater); por isso as `Reivindicacoes` devolvidas são as EXIGIDAS, e a camada
    validar_proveniencia confere de novo o conteúdo assinado do predicado.
    """

    def __init__(self, politica: Politica, cosign_bin: str = "/usr/local/bin/cosign", tempo_limite: int = 90, trusted_root: str | None = None):
        if not os.path.isabs(cosign_bin):
            raise ErroValidacao("cosign_bin deve ser caminho absoluto")
        if trusted_root is None or not os.path.isabs(trusted_root):
            raise ErroValidacao("trusted_root (raiz de confiança do Sigstore FIXADA) é obrigatória e deve ser caminho absoluto: sem ela o cosign precisa de rede")
        self.politica = politica
        self.cosign_bin = cosign_bin
        self.tempo_limite = tempo_limite
        self.trusted_root = trusted_root

    def argv(self, caminho_bundle: str, digest_sujeito: str, esperado: EsperadoCertificado) -> list:
        p = self.politica
        return [
            self.cosign_bin, "verify-blob-attestation",
            "--bundle", caminho_bundle,
            "--trusted-root", self.trusted_root,   # OFFLINE e fixada (validado com a rede bloqueada); sem isso o cosign busca a raiz via TUF
            "--type", "slsaprovenance1",
            "--digest", digest_sujeito.split(":", 1)[1],
            "--digestAlg", "sha256",
            "--certificate-identity", p.san_esperado,
            "--certificate-oidc-issuer", p.emissor,
            "--certificate-github-workflow-repository", p.repositorio,
            "--certificate-github-workflow-ref", p.ref,
            "--certificate-github-workflow-sha", esperado.commit,
            "--certificate-github-workflow-trigger", esperado.gatilho,
        ]

    def verificar(self, atestado: bytes, digest_sujeito: str, esperado: EsperadoCertificado) -> AtestadoVerificado:
        if not isinstance(atestado, (bytes, bytearray)) or not atestado or len(atestado) > MAX_ATESTADO:
            raise AtestadoInvalido("atestado ausente ou grande demais")
        try:
            bundle = json_estrito(bytes(atestado), MAX_ATESTADO)
            payload = base64.b64decode(bundle["dsseEnvelope"]["payload"], validate=True)
            declaracao = json_estrito(payload, MAX_ATESTADO)
        except (ErroValidacao, KeyError, TypeError, ValueError) as e:
            raise AtestadoInvalido("bundle sem envelope DSSE legível") from e  # contrato do backend: sempre AtestadoInvalido
        with tempfile.TemporaryDirectory(prefix="agente-cosign-") as pasta:
            os.chmod(pasta, 0o700)
            caminho = os.path.join(pasta, "bundle.json")
            fd = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, bytes(atestado))
            finally:
                os.close(fd)
            try:
                r = subprocess.run(
                    self.argv(caminho, digest_sujeito, esperado),
                    shell=False, stdin=subprocess.DEVNULL, capture_output=True, timeout=self.tempo_limite,
                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": pasta, "COSIGN_EXPERIMENTAL": "0"},
                    cwd=pasta, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as e:
                raise AtestadoInvalido("falha ao executar a verificação do atestado") from e
        if r.returncode != 0:
            raise AtestadoInvalido("assinatura do atestado NÃO verificada")
        p = self.politica
        return AtestadoVerificado(
            reivindicacoes=Reivindicacoes(
                emissor=p.emissor, san=p.san_esperado, repositorio=p.repositorio, ref=p.ref,
                sha=esperado.commit, evento=esperado.gatilho,
            ),
            declaracao=declaracao,
        )
