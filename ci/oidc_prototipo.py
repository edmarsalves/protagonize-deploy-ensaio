"""PROTÓTIPO DE ESTUDO (não integrado ao agente, não instalado em lugar nenhum): validação OFFLINE de um token OIDC do GitHub Actions só com a biblioteca padrão.

Ideia: o workflow pede o token com audiência `protagonize-publicacao:v1:<sha256 do manifesto>`; o GitHub assina (RS256) essa audiência junto das claims de
identidade. O validador (executor/verificador) confere assinatura, emissor, audiência (= hash do manifesto recebido), validade, claims e política.
HIPÓTESES NÃO PROVADAS COM TOKEN REAL: tempo de vida (exp), limite de tamanho da audiência, rotação das chaves (JWKS)."""
import base64, hashlib, json, re

EMISSOR = "https://token.actions.githubusercontent.com"
# DigestInfo do SHA-256 (RFC 8017, EMSA-PKCS1-v1_5)
_PREFIXO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")
PREFIXO_AUD = "protagonize-publicacao:v1:"


class TokenInvalido(Exception):
    def __init__(self, codigo, msg=""):
        super().__init__(f"{codigo}: {msg}")
        self.codigo = codigo


def _b64u(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise TokenInvalido("formato", "base64url inválido")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _json(b: bytes):
    def rejeita_duplicadas(pares):
        d = {}
        for k, v in pares:
            if k in d:
                raise TokenInvalido("formato", "chave JSON duplicada")
            d[k] = v
        return d
    try:
        obj = json.loads(b.decode("utf-8"), object_pairs_hook=rejeita_duplicadas)
    except (ValueError, UnicodeDecodeError) as e:
        raise TokenInvalido("formato", "JSON inválido") from e
    if not isinstance(obj, dict):
        raise TokenInvalido("formato", "esperado objeto")
    return obj


def _chave_publica(jwk: dict):
    if jwk.get("kty") != "RSA" or jwk.get("alg", "RS256") != "RS256" or jwk.get("use", "sig") != "sig":
        raise TokenInvalido("chave", "JWK não é RSA/RS256/sig")
    n, e = int.from_bytes(_b64u(jwk["n"]), "big"), int.from_bytes(_b64u(jwk["e"]), "big")
    if n.bit_length() < 2048 or e < 3 or e % 2 == 0:
        raise TokenInvalido("chave", "módulo/expoente inaceitáveis")
    return n, e


def _rs256_ok(n: int, e: int, assinado: bytes, assinatura: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(assinatura) != k:
        return False
    s = int.from_bytes(assinatura, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = _PREFIXO_SHA256 + hashlib.sha256(assinado).digest()
    esperado = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return em == esperado  # comparação do bloco INTEIRO (não aceita preenchimento frouxo)


def verificar_token(token: str, jwks: dict, *, agora: int, aud_esperada: str, idade_max_s: int = 900, tolerancia_s: int = 60, momento_do_manifesto: int | None = None) -> dict:
    """Modo 'portador' (padrão): o token precisa estar válido AGORA. Modo 'evidência' (`momento_do_manifesto` informado): o token é uma PROVA guardada, não uma
    credencial — exige-se que tenha sido emitido junto da criação do manifesto (iat ≤ criado_em ≤ exp, com tolerância) e que a idade do token não passe de `idade_max_s`
    (aqui a validade do ponteiro, p.ex. 7 dias); o `exp` curto do token NÃO invalida uma publicação processada depois. Replay continua barrado pelo seq e pela audiência."""
    partes = token.split(".") if isinstance(token, str) and len(token) < 16384 else []
    if len(partes) != 3:
        raise TokenInvalido("formato", "JWT deve ter 3 partes")
    cab, corpo = _json(_b64u(partes[0])), _json(_b64u(partes[1]))
    if cab.get("alg") != "RS256" or cab.get("typ", "JWT") != "JWT" or "crit" in cab:  # nunca 'none', HS*, nem outro algoritmo
        raise TokenInvalido("algoritmo", "somente RS256")
    kid = cab.get("kid")
    candidatas = [k for k in jwks.get("keys", []) if k.get("kid") == kid]
    if not kid or len(candidatas) != 1:
        raise TokenInvalido("chave", "kid desconhecido ou ambíguo")
    n, e = _chave_publica(candidatas[0])
    if not _rs256_ok(n, e, (partes[0] + "." + partes[1]).encode("ascii"), _b64u(partes[2])):
        raise TokenInvalido("assinatura", "assinatura RS256 inválida")
    if corpo.get("iss") != EMISSOR:
        raise TokenInvalido("emissor", "emissor inesperado")
    aud = corpo.get("aud")
    if not isinstance(aud, str) or aud != aud_esperada:  # string única e IGUAL (lista de audiências é recusada)
        raise TokenInvalido("audiencia", "audiência não corresponde ao manifesto")
    for c in ("iat", "exp", "nbf"):
        if type(corpo.get(c)) is not int:
            raise TokenInvalido("tempo", f"{c} ausente/inválido")
    if momento_do_manifesto is None:
        if corpo["exp"] + tolerancia_s < agora or corpo["nbf"] - tolerancia_s > agora or corpo["iat"] - tolerancia_s > agora:
            raise TokenInvalido("tempo", "token fora da validade")
    else:
        if not (corpo["iat"] - tolerancia_s <= momento_do_manifesto <= corpo["exp"] + tolerancia_s) or corpo["iat"] - tolerancia_s > agora:
            raise TokenInvalido("tempo", "o token não foi emitido junto da criação do manifesto")
    if agora - corpo["iat"] > idade_max_s:
        raise TokenInvalido("tempo", "token velho demais para este uso")
    return corpo


def audiencia_do_manifesto(manifesto_bytes: bytes) -> str:
    return PREFIXO_AUD + hashlib.sha256(manifesto_bytes).hexdigest()


def autorizar(corpo: dict, manifesto: dict, politica: dict, seq_atual: int) -> int:
    """Confere as claims (autenticadas pelo GitHub) com a política local E com o manifesto. Devolve a run_attempt."""
    def exige(cond, codigo, msg):
        if not cond:
            raise TokenInvalido(codigo, msg)
    s = lambda k: str(corpo.get(k))  # noqa: E731
    exige(s("repository_id") == politica["repositorio_id"] and s("repository_owner_id") == politica["dono_id"], "repositorio", "IDs imutáveis")
    exige(corpo.get("repository") == politica["repositorio"], "repositorio", "nome do repositório")
    exige(corpo.get("job_workflow_ref") == f"{politica['repositorio']}/{politica['workflow']}@{politica['ref']}", "workflow", "job_workflow_ref")
    exige(corpo.get("ref") == politica["ref"] and corpo.get("ref_type") == "branch", "ref", "ref")
    exige(corpo.get("event_name") in politica["eventos"], "evento", "evento")
    exige(corpo.get("runner_environment") == "github-hosted", "runner", "runner")
    exige(corpo.get("sha") == manifesto["commit"] and corpo.get("job_workflow_sha") == corpo.get("sha"), "commit", "sha")
    exige(re.fullmatch(r"[0-9]{1,20}", s("run_id")) and int(s("run_id")) == manifesto["seq"], "execucao", "run_id ≠ seq do manifesto")
    exige(re.fullmatch(r"[1-9][0-9]{0,5}", s("run_attempt")) and int(s("run_attempt")) == manifesto["tentativa_run"], "execucao", "run_attempt")
    exige(manifesto["seq"] > seq_atual, "sequencia", "replay/downgrade")
    return int(s("run_attempt"))


# ───────────── JWKS: busca com cache, rotação e indisponibilidade ─────────────
class JwksIndisponivel(Exception):
    """O JWKS não pôde ser obtido (transitório): quem chama ADIA, não rejeita nem põe em quarentena."""


class JwksCliente:
    """Obtém as chaves públicas do emissor. TLS verificado (urllib), tamanho limitado, tempo limitado. Mantém a última cópia BOA.
    • kid presente e cópia fresca → usa a cópia; • kid ausente → tenta renovar UMA vez (rotação); • rede fora → usa a cópia se o kid está nela (até `obsoleto_max_s`), senão JwksIndisponivel."""

    def __init__(self, url=EMISSOR + "/.well-known/jwks", *, buscar=None, ttl_s=3600, obsoleto_max_s=7 * 86400, relogio=None, max_bytes=65536):
        import time, urllib.request
        self.url, self.ttl_s, self.obsoleto_max_s, self.max_bytes = url, ttl_s, obsoleto_max_s, max_bytes
        self.relogio = relogio or time.time
        self.cache, self.quando = None, 0
        self.buscas = 0
        if buscar is None:
            def buscar(u):
                with urllib.request.urlopen(u, timeout=10) as f:
                    return f.read(max_bytes + 1)
        self._buscar = buscar

    def _renovar(self):
        self.buscas += 1
        try:
            bruto = self._buscar(self.url)
            if len(bruto) > self.max_bytes:
                raise ValueError("JWKS grande demais")
            obj = json.loads(bruto.decode("utf-8"))
            chaves = obj["keys"]
            if not isinstance(chaves, list) or not chaves or not all(isinstance(k, dict) and k.get("kty") == "RSA" and k.get("kid") for k in chaves):
                raise ValueError("JWKS fora do formato")
        except Exception as e:  # noqa: BLE001 - qualquer falha de rede/formato é "indisponível", nunca "aceito"
            raise JwksIndisponivel(f"JWKS indisponível: {type(e).__name__}") from None
        self.cache, self.quando = {"keys": chaves}, self.relogio()

    def obter(self, kid: str) -> dict:
        agora = self.relogio()
        if self.cache and agora - self.quando <= self.ttl_s and any(k["kid"] == kid for k in self.cache["keys"]):
            return self.cache
        try:
            self._renovar()
        except JwksIndisponivel:
            if self.cache and agora - self.quando <= self.obsoleto_max_s and any(k["kid"] == kid for k in self.cache["keys"]):
                return self.cache  # rede fora, mas a chave é conhecida e a cópia não é velha demais
            raise
        if not any(k["kid"] == kid for k in self.cache["keys"]):
            raise TokenInvalido("chave", "kid ausente mesmo após renovar o JWKS (chave revogada/desconhecida)")
        return self.cache


def verificar_com_jwks(token: str, cliente: JwksCliente, **kw) -> dict:
    partes = token.split(".") if isinstance(token, str) and len(token) < 16384 else []
    if len(partes) != 3:
        raise TokenInvalido("formato", "JWT deve ter 3 partes")
    kid = _json(_b64u(partes[0])).get("kid")
    if not isinstance(kid, str) or not kid:
        raise TokenInvalido("chave", "kid ausente")
    return verificar_token(token, cliente.obter(kid), **kw)
