"""EXECUTOR (único componente com privilégio na VPS; na prática roda como root).

Não fala com a rede para ler dado externo. Recebe um PACOTE do verificador, trata-o como NÃO CONFIÁVEL e REFAZ a verificação
completa (atestado + política) sobre um instantâneo em memória. Só então executa um conjunto FIXO de operações (acoes.Plataforma).

Garantias (cada uma tem teste):
  • nunca executa comando/caminho/nome de imagem vindo do pacote (só digests validados; nomes vêm da política);
  • seq monotônico (replay/downgrade recusados), quarentena de digests que falharam, limite de tentativas;
  • uma execução por vez (flock) e estado persistente que se recupera de queda;
  • rollback = SÓ imagem + 4 variáveis do .env. NÃO existe operação de banco de dados.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from . import canal
from .acoes import RE_IMAGEM_ENV, Plataforma, RefImagem
from .atestado import BackendAtestado, verificar_pacote
from .estado import Auditoria, Estado, gravar_status_publico
from .politica import Politica
from .util import (
    REDATOR,
    AtestadoIndisponivel,
    AtestadoInvalido,
    RE_HEX64,
    ErroAgente,
    ErroValidacao,
    EstadoCorrompido,
    Ocupado,
    ProvenienciaRejeitada,
    Trava,
    agora_utc,
    json_estrito,
)

# resultados
OCIOSO, RECUSADO, SEM_MUDANCA, PUBLICADO = "OCIOSO", "RECUSADO", "SEM_MUDANCA", "PUBLICADO"
REVERTIDO, FALHA_CRITICA, ADIADO, PAUSADO, OCUPADO = "REVERTIDO", "FALHA_CRITICA", "ADIADO", "PAUSADO", "OCUPADO"
MAX_PACOTES_POR_CICLO = 10
MAPA_RESULTADO_STATUS = {"ok": "ok", "sem_mudanca": "sem_mudanca", "revertido": "revertido", "falha_critica": "falhou_critico", "recusado_quarentena": "recusado", "tentativas_excedidas": "recusado"}
CODIGOS_SAIDA = {OCIOSO: 0, RECUSADO: 0, SEM_MUDANCA: 0, PUBLICADO: 0, PAUSADO: 0, ADIADO: 0, OCUPADO: 3, REVERTIDO: 1, FALHA_CRITICA: 2}


@dataclass
class ConfigExecutor:
    entrada: str
    quarentena_pacotes: str
    status_path: str
    pausar_arquivo: str
    trava: str
    manter_imagens: int = 3
    tempo_saudavel_s: int = 150
    tentativas_validacao: int = 4
    espera_validacao_s: float = 8.0
    uid_confiavel: int | None = None


class Executor:
    def __init__(self, politica: Politica, cfg: ConfigExecutor, estado: Estado, auditoria: Auditoria, plataforma: Plataforma,
                 backend: BackendAtestado, token_fn=None, relogio=agora_utc, dormir=time.sleep):
        self.politica, self.cfg, self.estado, self.aud = politica, cfg, estado, auditoria
        self.plat, self.backend = plataforma, backend
        self.token_fn = token_fn
        self.relogio, self.dormir = relogio, dormir

    def _reg(self, evento: str, **dados):
        """Auditoria de MELHOR ESFORÇO: uma falha da trilha (disco cheio, cauda ilegível) NUNCA pode impedir uma recuperação ou uma reversão."""
        try:
            return self.aud.registrar(evento, **dados)
        except Exception:  # noqa: BLE001
            return None

    # ───────────── entrada pública ─────────────
    def executar_uma_vez(self) -> str:
        """Processa recuperação + todos os pacotes pendentes (em ordem de seq). Devolve o resultado mais grave."""
        try:
            with Trava(self.cfg.trava):
                return self._ciclo()
        except Ocupado:
            return OCUPADO
        except ErroAgente as e:
            e.args = tuple(REDATOR.limpar(x) if isinstance(x, str) else x for x in e.args)
            raise
        except Exception as e:  # noqa: BLE001 - inesperada: registra higienizada e NÃO deixa o traceback original (pode conter segredo) escapar
            texto = REDATOR.limpar(f"{type(e).__name__}: {e}")
            try:
                self._reg("erro_inesperado", tipo=type(e).__name__, motivo=texto)
            except Exception:  # noqa: BLE001
                pass
            raise ErroAgente(texto) from None

    def _ciclo(self) -> str:
        self.estado.carregar()
        if self.estado.fase == "FALHA_CRITICA":
            self._reg("bloqueado_falha_critica")
            return FALHA_CRITICA
        pior = OCIOSO
        r = self._recuperar()
        if r == FALHA_CRITICA:
            return r
        if r is not None:
            pior = r  # a recuperação concluiu (PUBLICADO) ou reverteu (REVERTIDO) uma publicação interrompida
        if os.path.lexists(self.cfg.pausar_arquivo):
            self._reg("pausado")
            return PAUSADO if pior == OCIOSO else pior
        try:
            canal.limpar_temporarios(self.cfg.entrada)
            canal.podar_quarentena(self.cfg.quarentena_pacotes)
        except Exception:  # noqa: BLE001 - manutenção nunca derruba a publicação
            pass
        for caminho in self._pacotes_ordenados()[:MAX_PACOTES_POR_CICLO]:
            if os.path.lexists(self.cfg.pausar_arquivo):  # a pausa vale ENTRE pacotes, não só no início do ciclo
                self._reg("pausado")
                return PAUSADO if pior == OCIOSO else pior
            r = self._processar_pacote(caminho)
            if r == FALHA_CRITICA:
                return r
            if r == REVERTIDO:
                pior = REVERTIDO
            elif pior == OCIOSO and r != OCIOSO:
                pior = r
        return pior

    def _pacotes_ordenados(self) -> list:
        def chave(c):
            try:
                return (int(os.path.basename(c).split("-")[1]), os.path.basename(c))
            except (IndexError, ValueError):
                return (0, os.path.basename(c))
        return sorted(canal.listar_pacotes(self.cfg.entrada), key=chave)

    # ───────────── processamento de um pacote ─────────────
    def _processar_pacote(self, caminho: str) -> str:
        try:
            snapshot = canal.reivindicar_pacote(caminho, self.cfg.quarentena_pacotes, uid_confiavel=self.cfg.uid_confiavel)
        except ErroValidacao as e:
            # pacote NÃO verificado: só auditoria. Nunca toca o status público (um pacote forjado não pode apagar o resultado legítimo).
            self._reg("pacote_recusado", codigo="canal", motivo=str(e)[:200])
            return RECUSADO
        agora = self.relogio()
        try:
            versao = verificar_pacote(snapshot, self.politica, self.backend, agora)  # RE-VERIFICAÇÃO independente
        except AtestadoIndisponivel as e:
            self._reg("verificacao_indisponivel", motivo=str(e)[:200])  # a FERRAMENTA falhou (não é assinatura inválida): o verificador reentrega
            return ADIADO
        except (ErroValidacao, AtestadoInvalido, ProvenienciaRejeitada) as e:
            self._reg("pacote_recusado", codigo=getattr(e, "codigo", type(e).__name__), motivo=str(e)[:200])
            return RECUSADO
        except Exception as e:  # noqa: BLE001 - qualquer outra falha na verificação FALHA FECHADO (nunca derruba o ciclo nem publica)
            self._reg("pacote_recusado", codigo="erro_na_verificacao", motivo=REDATOR.limpar(f"{type(e).__name__}: {e}")[:200])
            return RECUSADO

        self._reg("pacote_verificado", seq=versao.seq, commit=versao.commit, gatilho=versao.gatilho, tipo=versao.tipo,
                  ponteiro=versao.digest_ponteiro, alvos=versao.alvos)
        ult = self.estado.dados["ultimo_resultado"] or {}
        if versao.seq <= self.estado.seq_atual:
            if versao.seq == self.estado.seq_atual and ult.get("ponteiro") == versao.digest_ponteiro:
                self._reg("ja_processado", seq=versao.seq)  # entrega duplicada do MESMO ponteiro: idempotente
                self._reemitir_status(ult, versao)  # e REPARA um status 'em_andamento' deixado por uma queda entre encerrar() e _status()
                return OCIOSO
            # replay: SÓ auditoria. NÃO escreve status público (um pacote antigo e autêntico não pode apagar o resultado da última publicação)
            self._reg("recusado_replay", seq=versao.seq, seq_atual=self.estado.seq_atual)
            return RECUSADO
        if any(self.estado.em_quarentena(d) for d in versao.alvos.values()):
            self._reg("recusado_quarentena", seq=versao.seq)
            self.estado.encerrar({"seq": versao.seq, "ponteiro": versao.digest_ponteiro, "commit": versao.commit, "resultado": "recusado_quarentena"}, consumir_seq=True)
            self._status(versao.seq, versao.commit, versao.digest_ponteiro, 0, "recusado", "digest_em_quarentena")
            return RECUSADO
        return self._publicar(versao)

    def _reemitir_status(self, ult: dict, versao) -> None:
        st = MAPA_RESULTADO_STATUS.get(ult.get("resultado"))
        if st:
            self._status(versao.seq, versao.commit, versao.digest_ponteiro, self.estado.dados["tentativas"].get(str(versao.seq), 0), st, ult.get("motivo", "reemitido"))

    def _publicar(self, versao) -> str:
        tentativa = self.estado.dados["tentativas"].get(str(versao.seq), 0)  # só CONTA quando uma troca realmente começar (falha de infraestrutura não queima o seq)
        S = (versao.seq, versao.commit, versao.digest_ponteiro, tentativa)
        atuais = self.plat.digests_em_execucao()
        servicos = [s for s, d in versao.alvos.items() if atuais.get(s) != d]
        if not servicos:
            self.estado.encerrar({"seq": versao.seq, "ponteiro": versao.digest_ponteiro, "commit": versao.commit, "resultado": "sem_mudanca"}, consumir_seq=True)
            self._reg("sem_mudanca", seq=versao.seq)
            self._status(*S, "sem_mudanca", "digests iguais aos em execucao")
            return SEM_MUDANCA
        problemas = self.plat.pre_checagens()
        if problemas:
            self._reg("adiado", seq=versao.seq, motivo=",".join(problemas))
            self._status(*S, "adiado", "pre_checagem: " + ",".join(problemas))
            return ADIADO
        env_atual = self.plat.referencias_env()
        for svc in servicos:  # o .env precisa estar na forma EXATA esperada ANTES de qualquer alteração (senão o estado persistido seria ilegível depois)
            par = env_atual.get(svc)
            if not (isinstance(par, tuple) and len(par) == 2 and RE_IMAGEM_ENV.match(str(par[0])) and RE_HEX64.match(str(par[1]))):
                self._reg("adiado", seq=versao.seq, motivo=f"env_fora_do_formato:{svc}")
                self._status(*S, "adiado", f"env_fora_do_formato:{svc}")
                return ADIADO

        antes = {s: atuais[s] for s in servicos if atuais.get(s)}
        env_antes = {s: [env_atual[s][0], env_atual[s][1]] for s in servicos}
        self.estado.iniciar(versao, antes, env_antes, servicos)
        self._status(*S, "em_andamento", "iniciado")
        self._reg("iniciado", seq=versao.seq, servicos=servicos)

        try:
            self.estado.fase_para("BACKUP")
            self.plat.checkpoint()
            self._reg("backup_ok", seq=versao.seq)
            self.estado.fase_para("BAIXANDO")
            refs = {s: RefImagem.da_politica(self.politica, s, versao.alvos[s]) for s in servicos}
            token = self.token_fn() if self.token_fn else None
            with self.plat.sessao_registro(token):
                for ref in refs.values():
                    if not self.plat.imagem_presente(ref):
                        self.plat.baixar(ref)
            self._reg("baixado", seq=versao.seq)
            tentativa = self.estado.contar_tentativa(versao.seq)  # conta UMA tentativa de TROCA (não de pré-checagem/download)
            S = (versao.seq, versao.commit, versao.digest_ponteiro, tentativa)
            if tentativa > self.politica.max_tentativas:
                self.estado.quarentenar(versao.alvos.values())
                self.estado.encerrar({"seq": versao.seq, "ponteiro": versao.digest_ponteiro, "commit": versao.commit, "resultado": "tentativas_excedidas"}, consumir_seq=True)
                self._reg("tentativas_excedidas", seq=versao.seq)
                self._status(*S, "recusado", "tentativas_excedidas")
                return RECUSADO
        except ErroAgente as e:  # nada foi alterado ainda: pode tentar de novo depois
            self._reg("adiado", seq=versao.seq, motivo=type(e).__name__ + ": " + REDATOR.limpar(e))
            self.estado.dados["fase"], self.estado.dados["em_curso"] = "OCIOSO", None
            self.estado.salvar()
            self._status(*S, "adiado", "falha_antes_da_troca")
            return ADIADO

        # ── a partir daqui há alteração: qualquer falha ⇒ reverte imagens/.env (NUNCA o banco)
        try:
            self.estado.fase_para("TROCANDO")
            mudancas = {s: (f"{refs[s].nome}@sha256", refs[s].hex) for s in servicos}
            self.plat.aplicar_env(mudancas)
            self.plat.recriar(servicos)
            self._reg("trocado", seq=versao.seq)
        except ErroAgente as e:
            self._reg("troca_falhou", seq=versao.seq, motivo=REDATOR.limpar(e))
            return self._reverter(versao, tentativa, servicos, "troca_falhou")
        return self._validar_e_concluir(versao, tentativa, servicos)

    def _validar_e_concluir(self, versao, tentativa: int, servicos: list) -> str:
        S = (versao.seq, versao.commit, versao.digest_ponteiro, tentativa)
        self.estado.fase_para("VALIDANDO")
        ok = self._validar_com_tentativas()
        if ok:
            atuais = self.plat.digests_em_execucao()
            ok = all(atuais.get(s) == versao.alvos[s] for s in servicos)
            if not ok:
                self._reg("digest_em_execucao_difere", seq=versao.seq)
        if not ok:
            self._reg("validacao_falhou", seq=versao.seq)
            return self._reverter(versao, tentativa, servicos, "validacao_falhou")
        self.estado.encerrar({"seq": versao.seq, "ponteiro": versao.digest_ponteiro, "commit": versao.commit, "resultado": "ok"}, consumir_seq=True)
        self._reg("publicado", seq=versao.seq, commit=versao.commit)
        self._status(*S, "ok", "publicado e validado")
        try:
            self.plat.limpar_imagens(self.cfg.manter_imagens)
        except ErroAgente as e:  # limpeza nunca derruba uma publicação que deu certo
            self._reg("limpeza_falhou", motivo=REDATOR.limpar(e))
        return PUBLICADO

    def _validar_com_tentativas(self) -> bool:
        if not self.plat.aguardar_saudavel(self.cfg.tempo_saudavel_s):
            pass  # a validação abaixo decide; saudável "tarde" ainda pode passar
        for i in range(self.cfg.tentativas_validacao):
            try:
                resultados = self.plat.validar()
            except ErroAgente as e:
                self._reg("validacao_erro", motivo=REDATOR.limpar(e))
                resultados = [("erro", False, "")]
            if resultados and all(ok for _, ok, _ in resultados):
                return True
            if i < self.cfg.tentativas_validacao - 1:
                self.dormir(self.cfg.espera_validacao_s)
        return False

    # ───────────── rollback (imagens + .env; nunca banco) ─────────────
    def _reverter(self, versao, tentativa: int, servicos: list, motivo: str) -> str:
        S = (versao.seq, versao.commit, versao.digest_ponteiro, tentativa)
        ec = self.estado.dados["em_curso"]
        self.estado.fase_para("REVERTENDO")
        self._reg("revertendo", seq=versao.seq, motivo=motivo)
        try:
            mudancas = {s: tuple(ec["env_antes"][s]) for s in servicos if s in ec["env_antes"]}
            if mudancas:
                self.plat.aplicar_env(mudancas)
            self.plat.recriar(servicos)
            if not self._validar_com_tentativas():
                raise ErroValidacao("validação reprovou também a versão anterior")
            atuais = self.plat.digests_em_execucao()
            if any(atuais.get(s) != ec["antes"].get(s) for s in servicos if s in ec["antes"]):
                raise ErroValidacao("digest após reversão difere do anterior")
        except ErroAgente as e:
            self._reg("falha_critica", seq=versao.seq, motivo=REDATOR.limpar(e))
            self.estado.encerrar({"seq": versao.seq, "ponteiro": versao.digest_ponteiro, "resultado": "falha_critica"}, consumir_seq=False, fase_final="FALHA_CRITICA")
            self._status(*S, "falhou_critico", "a reversao tambem falhou: intervencao humana")
            return FALHA_CRITICA
        self.estado.quarentenar(versao.alvos.values())
        self.estado.encerrar({"seq": versao.seq, "ponteiro": versao.digest_ponteiro, "commit": versao.commit, "resultado": "revertido", "motivo": motivo}, consumir_seq=True)
        self._reg("revertido", seq=versao.seq, motivo=motivo)
        self._status(*S, "revertido", motivo)
        return REVERTIDO

    # ───────────── recuperação após reinício/queda ─────────────
    def _recuperar(self) -> str | None:
        fase, ec = self.estado.fase, self.estado.dados["em_curso"]
        if fase == "OCIOSO" or ec is None:
            return None
        self._reg("recuperacao", fase=fase, seq=ec["seq"])
        from .atestado import VersaoAutorizada  # tipo só para reaproveitar os helpers
        from .util import parse_iso_utc
        versao = VersaoAutorizada(seq=ec["seq"], commit=ec["commit"], gatilho="recuperacao", tipo="release", digest_ponteiro=ec["digest_ponteiro"],
                                  criado_em=parse_iso_utc(ec["iniciado_em"]), alvos=dict(ec["alvo"]))
        tentativa = self.estado.dados["tentativas"].get(str(ec["seq"]), 1)
        servicos = list(ec["servicos"])
        if fase in ("RECEBIDO", "BACKUP", "BAIXANDO"):  # nada foi alterado
            self.estado.dados["fase"], self.estado.dados["em_curso"] = "OCIOSO", None
            self.estado.salvar()
            self._status(versao.seq, versao.commit, versao.digest_ponteiro, tentativa, "adiado", "interrompido_antes_da_troca")
            return None
        if fase == "REVERTENDO":
            return self._reverter(versao, tentativa, servicos, "retomada_da_reversao")
        atuais = self.plat.digests_em_execucao()
        env = self.plat.referencias_env()
        alvo_no_ar = all(atuais.get(s) == versao.alvos[s] for s in servicos)
        tudo_antes = all(atuais.get(s) == ec["antes"].get(s) for s in servicos if s in ec["antes"]) and all(
            list(env.get(s, ("", ""))) == ec["env_antes"].get(s) for s in servicos if s in ec["env_antes"])
        if fase == "VALIDANDO" or (fase == "TROCANDO" and alvo_no_ar):
            return self._validar_e_concluir(versao, tentativa, servicos)
        if fase == "TROCANDO" and tudo_antes:  # nada chegou a mudar
            self.estado.dados["fase"], self.estado.dados["em_curso"] = "OCIOSO", None
            self.estado.salvar()
            return None
        return self._reverter(versao, tentativa, servicos, "queda_durante_a_troca")

    def liberar_quarentena(self, digest: str, operador: str) -> None:
        """Comando HUMANO e AUDITADO: tira um digest da quarentena (ex.: um digest saudável reutilizado por um release legítimo)."""
        from .util import exigir_digest
        exigir_digest(digest, "digest")
        with Trava(self.cfg.trava):
            self.estado.carregar()
            if digest not in self.estado.dados["quarentena"]:
                raise ErroValidacao("o digest não está em quarentena")
            self.estado.dados["quarentena"].remove(digest)
            self.estado.salvar()
            self._reg("quarentena_liberada", digest=digest, operador=str(operador)[:64])

    def reinicializar_estado(self, operador: str) -> int:
        """Comando HUMANO e AUDITADO: único caminho para um estado ilegível/ausente. Recomeça com seq_atual = âncora (nunca menos); a quarentena se perde (fica na auditoria)."""
        with Trava(self.cfg.trava):
            ancora = self.estado.reinicializar()
            self._reg("estado_reinicializado", operador=str(operador)[:64], seq_atual=ancora)
            return ancora

    def reconhecer_falha_critica(self, operador: str) -> None:
        """Único caminho para sair de FALHA_CRITICA: decisão HUMANA registrada (o agente nunca se 'cura' sozinho). Toma a trava (não concorre com a publicação)."""
        with Trava(self.cfg.trava):
            self._reconhecer(operador)

    def _reconhecer(self, operador: str) -> None:
        self.estado.carregar()
        if self.estado.fase != "FALHA_CRITICA":
            raise ErroValidacao("não há falha crítica pendente")
        ec = self.estado.dados["em_curso"]
        if ec:
            self.estado.quarentenar(ec["alvo"].values())
            self.estado.dados["seq_atual"] = max(self.estado.seq_atual, ec["seq"])
        self.estado.dados["fase"], self.estado.dados["em_curso"] = "OCIOSO", None
        self.estado.salvar()
        self._reg("falha_critica_reconhecida", operador=str(operador)[:64])

    # ───────────── status público (sem credencial de escrita no GitHub) ─────────────
    def _status(self, seq, commit, ponteiro, tentativa, status, motivo) -> None:
        gravar_status_publico(self.cfg.status_path, seq=seq, commit=commit, ponteiro=ponteiro, tentativa=tentativa, status=status,
                              motivo=motivo, relogio=self.relogio)
