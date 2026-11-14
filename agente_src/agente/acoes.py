"""As ÚNICAS operações que o executor pode realizar sobre a VPS (lista fixa) e suas duas implementações.

  Plataforma           — interface. Não existe operação de banco de dados (restaurar/apagar): o rollback é SÓ de imagem + .env.
  PlataformaDocker     — produção: argv fixos, shell=False, ambiente mínimo, sem receber comando/caminho/nome de imagem de fora.
  PlataformaSimulada   — descartável (--simulado e testes): estado em arquivos, injeção de falhas e registro das chamadas.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .politica import Politica
from .util import (
    REDATOR,
    ErroValidacao,
    RE_DIGEST,
    RE_HEX64,
    escrever_atomico,
    exigir_digest,
    ler_arquivo_seguro,
)

OPERACOES_PERMITIDAS = (
    "pre_checagens", "digests_em_execucao", "referencias_env", "checkpoint", "imagem_presente", "baixar",
    "aplicar_env", "recriar", "aguardar_saudavel", "validar", "limpar_imagens", "sessao_registro",
)
VARIAVEIS_ENV = {"api": ("API_IMAGE", "API_TAG"), "web": ("WEB_IMAGE", "WEB_TAG")}
RE_NOME_IMAGEM = re.compile(r"\A[a-z0-9]([a-z0-9.-]{1,62})/[a-z0-9][a-z0-9-]{0,38}/[a-z0-9][a-z0-9._-]{0,63}\Z")
RE_IMAGEM_ENV = re.compile(r"\A[A-Za-z0-9.:/_-]{3,200}@sha256\Z")


@dataclass(frozen=True)
class RefImagem:
    """Referência de imagem JÁ VALIDADA. Só é possível criá-la a partir da política (nome autorizado) + digest válido."""
    servico: str
    nome: str
    digest: str

    def __post_init__(self):
        if self.servico not in ("api", "web"):
            raise ErroValidacao("serviço desconhecido")
        if not RE_NOME_IMAGEM.match(self.nome):
            raise ErroValidacao("nome de imagem fora do formato")
        exigir_digest(self.digest, "digest")

    @classmethod
    def da_politica(cls, politica: Politica, servico: str, digest: str) -> "RefImagem":
        return cls(servico=servico, nome=politica.nome_imagem(servico), digest=digest)

    @property
    def hex(self) -> str:
        return self.digest.split(":", 1)[1]

    def __str__(self) -> str:
        return f"{self.nome}@{self.digest}"


def editar_env_imagens(texto: str, mudancas: dict) -> str:
    """Troca SOMENTE as quatro variáveis de imagem do .env ({svc: (imagem@sha256, hex)}). Nada mais pode mudar."""
    linhas = texto.split("\n")
    for svc, (imagem, hexa) in mudancas.items():
        if svc not in VARIAVEIS_ENV:
            raise ErroValidacao("serviço desconhecido")
        if not RE_IMAGEM_ENV.match(imagem) or not RE_HEX64.match(hexa):
            raise ErroValidacao("valor de imagem inválido para o .env")
        var_img, var_tag = VARIAVEIS_ENV[svc]
        for var, valor in ((var_img, imagem), (var_tag, hexa)):
            idx = [i for i, l in enumerate(linhas) if l.startswith(var + "=")]
            if len(idx) != 1:
                raise ErroValidacao(f"{var} deve aparecer exatamente uma vez no .env")
            linhas[idx[0]] = f"{var}={valor}"
    return "\n".join(linhas)


class Plataforma(ABC):
    @abstractmethod
    def pre_checagens(self) -> list: ...
    @abstractmethod
    def digests_em_execucao(self) -> dict: ...
    @abstractmethod
    def referencias_env(self) -> dict: ...
    @abstractmethod
    def checkpoint(self) -> str: ...
    @abstractmethod
    def imagem_presente(self, ref: RefImagem) -> bool: ...
    @abstractmethod
    def baixar(self, ref: RefImagem) -> None: ...
    @abstractmethod
    def aplicar_env(self, mudancas: dict) -> None: ...
    @abstractmethod
    def recriar(self, servicos: list) -> None: ...
    @abstractmethod
    def aguardar_saudavel(self, timeout_s: int) -> bool: ...
    @abstractmethod
    def validar(self) -> list: ...
    @abstractmethod
    def limpar_imagens(self, manter: int) -> list: ...
    @abstractmethod
    def sessao_registro(self, token: str | None): ...


# ───────────────────────── produção ─────────────────────────


@dataclass
class ConfigDocker:
    docker_bin: str
    env_file: str
    chaves_env: str
    compose_arquivos: list
    containers: dict  # {"api": "...", "web": "...", "postgres": "..."}
    checkpoint_cmd: list
    validacoes: list  # [{"nome","caminho","esperado"}]
    registro_host: str = "ghcr.io"
    registro_usuario: str = "conta-de-servico"
    cofre_dir: str = "/mnt/protagonize-dados"
    disco_max_pct: int = 90
    tempo_comando: int = 300
    http: object = None  # objeto com .status(caminho) -> int
    dormir: object = time.sleep


class PlataformaDocker(Plataforma):
    def __init__(self, cfg: ConfigDocker, politica: Politica):
        for caminho in [cfg.docker_bin, cfg.env_file, cfg.chaves_env, *cfg.compose_arquivos, cfg.checkpoint_cmd[0]]:
            if not os.path.isabs(caminho):
                raise ErroValidacao("a configuração só aceita caminhos absolutos")
        self.cfg = cfg
        self.politica = politica
        self._docker_config: str | None = None

    # execução: argv fixo, sem shell, ambiente mínimo (nada herdado: sem API_TAG/WEB_TAG nem credenciais do chamador)
    def _executar(self, argv, *, entrada: str | None = None, tempo: int | None = None):
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C", "HOME": "/root"}
        if self._docker_config:
            env["DOCKER_CONFIG"] = self._docker_config
        try:
            r = subprocess.run(
                argv, shell=False, input=(entrada.encode() if entrada else None), stdin=None if entrada else subprocess.DEVNULL,
                capture_output=True, timeout=tempo or self.cfg.tempo_comando, env=env, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise ErroValidacao(f"falha ao executar {os.path.basename(argv[0])}: {REDATOR.limpar(e)}") from e
        return r

    def _docker(self, *args, **kw):
        return self._executar([self.cfg.docker_bin, *args], **kw)

    def pre_checagens(self) -> list:
        problemas = []
        if not os.path.ismount(self.cfg.cofre_dir):
            problemas.append("cofre fechado")
        uso = shutil.disk_usage("/")
        if uso.used * 100 // uso.total >= self.cfg.disco_max_pct:
            problemas.append("disco quase cheio")
        pg = self.cfg.containers.get("postgres")
        if pg and self._docker("exec", pg, "pg_isready", "-q").returncode != 0:
            problemas.append("PostgreSQL indisponível")
        return problemas

    def digests_em_execucao(self) -> dict:
        saida = {}
        for svc in ("api", "web"):
            r = self._docker("inspect", "-f", "{{.Image}}", self.cfg.containers[svc])
            valor = r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""
            saida[svc] = valor if RE_DIGEST.match(valor) else None
        return saida

    def referencias_env(self) -> dict:
        texto = ler_arquivo_seguro(self.cfg.env_file, 64 * 1024, uid_dono=0 if os.geteuid() == 0 else None).decode("utf-8")
        valores = dict(l.split("=", 1) for l in texto.split("\n") if "=" in l and not l.startswith("#"))
        return {svc: (valores.get(v[0], ""), valores.get(v[1], "")) for svc, v in VARIAVEIS_ENV.items()}

    def checkpoint(self) -> str:
        r = self._executar(list(self.cfg.checkpoint_cmd), tempo=900)
        if r.returncode != 0:
            raise ErroValidacao("checkpoint falhou")
        return "ok"

    def imagem_presente(self, ref: RefImagem) -> bool:
        return self._docker("image", "inspect", "--format", "{{json .RepoDigests}}", str(ref)).returncode == 0

    def baixar(self, ref: RefImagem) -> None:
        if ref.nome != self.politica.nome_imagem(ref.servico):
            raise ErroValidacao("imagem fora da lista autorizada")
        r = self._docker("pull", "-q", str(ref))
        if r.returncode != 0:
            raise ErroValidacao("não foi possível baixar a imagem")
        r = self._docker("image", "inspect", "--format", "{{json .RepoDigests}}", str(ref))
        if r.returncode != 0 or str(ref) not in r.stdout.decode("utf-8", "replace"):
            raise ErroValidacao("a imagem baixada não confere com o digest pedido")

    def aplicar_env(self, mudancas: dict) -> None:
        texto = ler_arquivo_seguro(self.cfg.env_file, 64 * 1024).decode("utf-8")
        novo = editar_env_imagens(texto, mudancas)
        modo = os.stat(self.cfg.env_file).st_mode & 0o777
        escrever_atomico(self.cfg.env_file, novo.encode("utf-8"), modo)

    def recriar(self, servicos: list) -> None:
        if not servicos or any(s not in ("api", "web") for s in servicos):
            raise ErroValidacao("serviços inválidos")
        argv = [self.cfg.docker_bin, "compose", "--env-file", self.cfg.env_file, "--env-file", self.cfg.chaves_env]
        for arq in self.cfg.compose_arquivos:
            argv += ["-f", arq]
        argv += ["up", "-d", "--no-deps", "--force-recreate", *servicos]
        r = self._executar(argv)
        if r.returncode != 0:
            raise ErroValidacao("falha ao recriar serviços")

    def aguardar_saudavel(self, timeout_s: int) -> bool:
        limite = time.monotonic() + timeout_s
        while time.monotonic() < limite:
            r = self._docker("inspect", "-f", "{{.State.Health.Status}}", self.cfg.containers["api"])
            if r.returncode == 0 and r.stdout.decode().strip() == "healthy":
                return True
            self.cfg.dormir(3)
        return False

    def validar(self) -> list:
        resultados = []
        for v in self.cfg.validacoes:
            try:
                obtido = self.cfg.http.status(v["caminho"])
            except Exception as e:  # noqa: BLE001 - qualquer falha de rede = validação reprovada
                resultados.append((v["nome"], False, REDATOR.limpar(type(e).__name__)))
                continue
            resultados.append((v["nome"], obtido == v["esperado"], f"{obtido} (esperado {v['esperado']})"))
        return resultados

    def limpar_imagens(self, manter: int) -> list:
        # Mantém as `manter` imagens mais novas de cada repositório autorizado e as em uso; remove o resto.
        removidas = []
        em_uso = {d for d in self.digests_em_execucao().values() if d}
        for papel in ("api", "web"):
            nome = self.politica.nome_imagem(papel)
            r = self._docker("images", "--no-trunc", "--format", "{{.ID}} {{.Repository}}", nome)
            ids = []
            for linha in r.stdout.decode("utf-8", "replace").splitlines():
                partes = linha.split(" ")
                if len(partes) == 2 and partes[1] == nome and RE_DIGEST.match(partes[0]) and partes[0] not in ids:
                    ids.append(partes[0])
            for velho in ids[manter:]:
                if velho not in em_uso and self._docker("rmi", velho).returncode == 0:
                    removidas.append(velho)
        return removidas

    @contextlib.contextmanager
    def sessao_registro(self, token: str | None):
        """Login TEMPORÁRIO no registro (diretório de configuração descartável); nada fica gravado."""
        if not token:
            yield
            return
        pasta = tempfile.mkdtemp(prefix="agente-docker-")
        os.chmod(pasta, 0o700)
        self._docker_config = pasta
        try:
            r = self._docker("login", self.cfg.registro_host, "-u", self.cfg.registro_usuario, "--password-stdin", entrada=token)
            if r.returncode != 0:
                raise ErroValidacao("login no registro falhou")
            yield
        finally:
            self._docker_config = None
            shutil.rmtree(pasta, ignore_errors=True)


# ───────────────────────── simulação descartável ─────────────────────────


class PlataformaSimulada(Plataforma):
    """Estado em arquivos dentro de `pasta`. Falhas injetáveis por `falhas.json` (só existe aqui, nunca na PlataformaDocker)."""

    def __init__(self, pasta: str, politica: Politica):
        self.pasta = pasta
        self.politica = politica
        os.makedirs(pasta, exist_ok=True)
        self._host = os.path.join(pasta, "host.json")
        self._falhas = os.path.join(pasta, "falhas.json")
        self._log = os.path.join(pasta, "chamadas.jsonl")

    # estado do "host" simulado
    def _ler(self) -> dict:
        with open(self._host, "r", encoding="utf-8") as f:
            return json.load(f)

    def _gravar(self, h: dict) -> None:
        escrever_atomico(self._host, json.dumps(h, sort_keys=True).encode(), 0o600)

    def _registrar(self, op: str, **dados) -> None:
        if op not in OPERACOES_PERMITIDAS:
            raise AssertionError(f"operação fora da lista fixa: {op}")
        with open(self._log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"op": op, **{k: str(v) for k, v in dados.items()}}) + "\n")

    def _falha(self, op: str):
        if not os.path.exists(self._falhas):
            return None
        with open(self._falhas, "r", encoding="utf-8") as f:
            falhas = json.load(f)
        cfg = falhas.get(op)
        if not cfg or cfg.get("vezes", 0) <= 0:
            return None
        cfg["vezes"] -= 1
        escrever_atomico(self._falhas, json.dumps(falhas).encode(), 0o600)
        return cfg.get("modo", "erro")

    def _aplicar_falha(self, op: str):
        modo = self._falha(op)
        if modo == "crash":
            os._exit(137)  # simula 'kill -9' no meio da operação
        if modo == "dormir":
            time.sleep(2.0)  # segura a trava por um tempo (teste de concorrência)
            return None
        if modo == "erro":
            raise ErroValidacao(f"falha simulada em {op}")
        return modo

    # operações
    def pre_checagens(self) -> list:
        self._registrar("pre_checagens")
        return list(self._ler().get("problemas", []))

    def digests_em_execucao(self) -> dict:
        self._registrar("digests_em_execucao")
        return dict(self._ler()["em_execucao"])

    def referencias_env(self) -> dict:
        self._registrar("referencias_env")
        return {k: tuple(v) for k, v in self._ler()["env"].items()}

    def checkpoint(self) -> str:
        self._registrar("checkpoint")
        self._aplicar_falha("checkpoint")
        h = self._ler()
        h["checkpoints"] = h.get("checkpoints", 0) + 1
        self._gravar(h)
        return "ok"

    def imagem_presente(self, ref: RefImagem) -> bool:
        self._registrar("imagem_presente", ref=ref)
        return str(ref) in self._ler()["locais"]

    def baixar(self, ref: RefImagem) -> None:
        self._registrar("baixar", ref=ref)
        modo = self._aplicar_falha("baixar")
        h = self._ler()
        if str(ref) not in h["remotas"]:
            raise ErroValidacao("imagem inexistente no registro simulado")
        if modo == "corromper":
            raise ErroValidacao("a imagem baixada não confere com o digest pedido")
        if str(ref) not in h["locais"]:
            h["locais"].append(str(ref))
        self._gravar(h)

    def aplicar_env(self, mudancas: dict) -> None:
        self._registrar("aplicar_env", mudancas=mudancas)
        self._aplicar_falha("aplicar_env")
        h = self._ler()
        for svc, (imagem, hexa) in mudancas.items():
            if svc not in VARIAVEIS_ENV or not RE_IMAGEM_ENV.match(imagem) or not RE_HEX64.match(hexa):
                raise ErroValidacao("valor inválido para o .env")
            h["env"][svc] = [imagem, hexa]
        self._gravar(h)

    def recriar(self, servicos: list) -> None:
        self._registrar("recriar", servicos=servicos)
        modo = self._aplicar_falha("recriar")
        h = self._ler()
        for i, svc in enumerate(servicos):
            if modo == "parcial" and i == 1:
                self._gravar(h)
                raise ErroValidacao("recriação parcial simulada")
            h["em_execucao"][svc] = "sha256:" + h["env"][svc][1]
        self._gravar(h)

    def aguardar_saudavel(self, timeout_s: int) -> bool:
        self._registrar("aguardar_saudavel")
        return not self._ruins_rodando()

    def _ruins_rodando(self) -> bool:
        h = self._ler()
        return any(d in set(h.get("ruins", [])) for d in h["em_execucao"].values())

    def validar(self) -> list:
        self._registrar("validar")
        self._aplicar_falha("validar")
        ruim = self._ruins_rodando()
        return [("api_saudavel", not ruim, "simulado"), ("site_publico", not ruim, "simulado"), ("rede_do_web", True, "simulado")]

    def limpar_imagens(self, manter: int) -> list:
        self._registrar("limpar_imagens", manter=manter)
        return []

    @contextlib.contextmanager
    def sessao_registro(self, token: str | None):
        self._registrar("sessao_registro", com_token=bool(token))
        yield


def criar_cenario_simulado(pasta: str, politica: Politica, atuais: dict, remotas: list, ruins: list | None = None) -> PlataformaSimulada:
    """Cria o 'host' descartável: `atuais` = {svc: digest}; `remotas` = digests (com serviço) disponíveis no registro simulado."""
    p = PlataformaSimulada(pasta, politica)
    env = {s: [f"{politica.nome_imagem(s)}@sha256", d.split(":", 1)[1]] for s, d in atuais.items()}
    locais = [f"{politica.nome_imagem(s)}@{d}" for s, d in atuais.items()]
    host = {
        "em_execucao": dict(atuais), "env": env, "locais": locais, "remotas": [f"{politica.nome_imagem(s)}@{d}" for s, d in remotas] + locais,
        "ruins": list(ruins or []), "problemas": [], "checkpoints": 0,
    }
    p._gravar(host)
    return p
