"""Job FINAL do fluxo do GitHub: decide se a publicação ESPERADA terminou bem, lendo o /_versao.json público.

Regras anti-engano (cada uma tem teste):
  • resultado ANTIGO ou de OUTRA publicação nunca vale como o da publicação esperada (compara seq E digest do ponteiro);
  • resultado com o mesmo seq porém commit/ponteiro diferentes = FALHA (inconsistente), não sucesso;
  • resultado gerado ANTES de o ponteiro existir é ignorado;
  • status ilegível/fora do esquema ⇒ continua aguardando (e o fluxo falha por tempo), nunca sucesso.
Somente biblioteca padrão (roda no runner do GitHub).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .estado import STATUS_PUBLICOS
from .util import ErroValidacao, exigir_chaves_exatas, exigir_commit, exigir_digest, exigir_inteiro, json_estrito, parse_iso_utc

AGUARDAR, SUCESSO, FALHA, SUPERADO = "AGUARDAR", "SUCESSO", "FALHA", "SUPERADO"


@dataclass(frozen=True)
class EsperadoStatus:
    seq: int
    commit: str
    ponteiro: str
    criado_em: datetime


def _higienizar(texto) -> str:
    """O motivo vem de um arquivo público: só caracteres inofensivos, sem '::' (comandos de workflow do GitHub), sem quebras/controle, tamanho limitado."""
    import re
    t = re.sub(r"[^A-Za-z0-9 ._,;:/@=()\-]", "?", str(texto)[:200])
    while "::" in t:
        t = t.replace("::", ": ")
    return t


def avaliar_status(bruto: bytes, esperado: EsperadoStatus) -> tuple:
    try:
        obj = json_estrito(bruto, 8192)
        exigir_chaves_exatas(obj, {"esquema", "seq", "commit", "ponteiro", "tentativa", "status", "motivo", "gerado_em", "concluido_em"}, set(), "status")
        if obj["esquema"] != 1 or obj["status"] not in STATUS_PUBLICOS:
            raise ErroValidacao("status fora do esquema")
        gerado = parse_iso_utc(obj["gerado_em"], "gerado_em")
        concluido = parse_iso_utc(obj["concluido_em"], "concluido_em") if obj["concluido_em"] is not None else None
        seq = obj["seq"]
        if seq is not None:
            exigir_inteiro(seq, "seq")
        if obj["commit"] is not None:
            exigir_commit(obj["commit"], "commit")
        if obj["ponteiro"] is not None:
            exigir_digest(obj["ponteiro"], "ponteiro")
    except ErroValidacao as e:
        return AGUARDAR, f"status ilegível/inválido ({e})"

    if seq is not None and seq > esperado.seq and obj["ponteiro"] != esperado.ponteiro:
        return SUPERADO, "uma publicação mais nova já foi processada"
    if seq != esperado.seq or obj["ponteiro"] != esperado.ponteiro:
        return AGUARDAR, "o status é de OUTRA publicação (resultado antigo não vale)"
    if obj["commit"] != esperado.commit:
        return FALHA, "status com o mesmo seq/ponteiro mas commit diferente (inconsistente)"
    if gerado < esperado.criado_em or (concluido is not None and concluido < esperado.criado_em):
        return AGUARDAR, "status anterior à criação do ponteiro (resultado velho)"
    if obj["status"] in ("ok", "sem_mudanca"):
        return SUCESSO, obj["status"]
    if obj["status"] in ("revertido", "falhou_critico", "recusado"):
        return FALHA, f"{obj['status']}: {_higienizar(obj['motivo'])}"
    return AGUARDAR, obj["status"]  # em_andamento | adiado
