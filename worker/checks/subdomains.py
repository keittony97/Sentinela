"""Enumeração passiva de subdomínios via Certificate Transparency (crt.sh).

Ferramenta "subdomains": 100% passiva — consulta um banco de dados
público de certificados TLS já emitidos, nunca toca o alvo diretamente.
Disponível em qualquer modalidade legal.
"""

from urllib.parse import urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

# TLDs de dois níveis comuns — sem isso, "sub.example.com.br" seria tratado
# como apex "com.br". Não é uma lista exaustiva (a lista pública oficial é
# a Public Suffix List), mas cobre os casos mais comuns pra um MVP.
TWO_LEVEL_TLDS = {"com.br", "net.br", "org.br", "gov.br", "co.uk", "org.uk", "com.au", "co.jp"}

SENSITIVE_KEYWORDS = [
    "dev",
    "staging",
    "stg",
    "test",
    "homolog",
    "hml",
    "uat",
    "internal",
    "intranet",
    "admin",
    "vpn",
    "backup",
    "old",
    "legacy",
    "api-dev",
    "sandbox",
]


def _apex_domain(hostname: str) -> str:
    labels = hostname.lower().split(".")
    if len(labels) <= 2:
        return hostname.lower()
    last_two = ".".join(labels[-2:])
    if last_two in TWO_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o domínio de {url}")
        return logs, findings

    apex = _apex_domain(hostname)
    log("info", f"Consultando crt.sh (Certificate Transparency) para *.{apex}")

    try:
        resp = httpx.get(
            "https://crt.sh/", params={"q": f"%.{apex}", "output": "json"}, timeout=30
        )
        resp.raise_for_status()
        entries = resp.json()
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao consultar crt.sh: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível consultar o Certificate Transparency",
                "cwe": None,
                "owasp_category": None,
                "description": f"A consulta a crt.sh para *.{apex} falhou: {exc}",
                "impact": "Não foi possível mapear subdomínios públicos por essa via.",
                "recommendation": "Tentar novamente mais tarde ou usar outra fonte passiva (ex: DNS público, motores de busca).",
                "reference_links": ["https://crt.sh/"],
                "evidence": {"apex": apex, "error": str(exc)},
            }
        )
        return logs, findings

    subdomains: set[str] = set()
    for entry in entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and name.endswith(apex) and "*" not in name:
                subdomains.add(name)

    log("info", f"{len(subdomains)} subdomínio(s) único(s) encontrado(s) via certificados públicos")

    interesting = sorted(s for s in subdomains if any(k in s for k in SENSITIVE_KEYWORDS))

    if interesting:
        log(
            "warning",
            f"{len(interesting)} subdomínio(s) com nome potencialmente sensível: {', '.join(interesting[:10])}",
        )
        findings.append(
            {
                "severity": "baixo",
                "title": f"{len(interesting)} subdomínio(s) com nome potencialmente sensível expostos publicamente",
                "cwe": "CWE-200",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "description": (
                    "Certificados TLS públicos (Certificate Transparency) revelam subdomínios "
                    "com nomes que sugerem ambientes de desenvolvimento, homologação ou "
                    "administração: " + ", ".join(interesting[:30])
                ),
                "impact": "Ambientes não-produtivos costumam ter controles de segurança mais fracos (senhas padrão, debug habilitado, dados de teste) e podem expor dados ou funcionalidades sensíveis se acessíveis publicamente.",
                "recommendation": "Revisar se cada subdomínio precisa ser publicamente resolvível/acessível; restringir por VPN, IP allowlist ou autenticação adicional quando não precisar estar público.",
                "reference_links": ["https://crt.sh/", "https://owasp.org/www-project-web-security-testing-guide/"],
                "evidence": {"subdomains": interesting},
            }
        )
    else:
        log("info", "Nenhum subdomínio com nome obviamente sensível encontrado.")

    findings.append(
        {
            "severity": "informativo",
            "title": f"{len(subdomains)} subdomínio(s) público(s) encontrados via Certificate Transparency",
            "cwe": None,
            "owasp_category": None,
            "description": f"Consulta a crt.sh para *.{apex} retornou {len(subdomains)} nome(s) único(s).",
            "impact": "Mapeamento de superfície de ataque — não é uma vulnerabilidade por si só, mas informa o escopo real exposto publicamente.",
            "recommendation": "Revisar a lista completa (nas evidências) e confirmar que todo subdomínio listado é intencional.",
            "reference_links": ["https://crt.sh/"],
            "evidence": {"subdomains": sorted(subdomains)[:300]},
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
