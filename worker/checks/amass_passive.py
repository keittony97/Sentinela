"""Enumeração passiva de subdomínios via Amass (modo passivo).

Ferramenta "amass_passive": roda `amass enum -passive`, que só agrega
dados de fontes públicas de terceiros (Certificate Transparency, motores
de busca, datasets abertos) — nunca envia tráfego de DNS/HTTP direto
contra o alvo. Complementa "subdomains" (crt.sh direto): o Amass agrega
várias fontes ao mesmo tempo, então tende a achar mais nomes.
"""

import json
import shutil
import subprocess
from urllib.parse import urlparse

TWO_LEVEL_TLDS = {"com.br", "net.br", "org.br", "gov.br", "co.uk", "org.uk", "com.au", "co.jp"}

SENSITIVE_KEYWORDS = [
    "dev", "staging", "stg", "test", "homolog", "hml", "uat",
    "internal", "intranet", "admin", "vpn", "backup", "old", "legacy",
]

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"


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

    domain = _apex_domain(hostname)

    amass_binary = shutil.which("amass")
    if not amass_binary:
        log("warning", "Amass não encontrado nesta máquina — usando só 'subdomains' (crt.sh) como fonte passiva.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Enumeração via Amass não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'amass_passive' precisa do binário 'amass' disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo. A ferramenta 'subdomains' (crt.sh) já cobre uma fonte passiva de subdomínios.",
                "recommendation": "Instalar o Amass na máquina/container do worker (https://github.com/owasp-amass/amass) para agregar mais fontes públicas.",
                "reference_links": ["https://github.com/owasp-amass/amass"],
                "evidence": {"domain": domain},
            }
        )
        return logs, findings

    log("info", f"Rodando Amass em modo passivo (-passive) contra {domain} — só fontes públicas, sem tocar o alvo")
    try:
        result = subprocess.run(
            [amass_binary, "enum", "-passive", "-d", domain, "-json", "-"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log("error", "Amass excedeu o tempo limite (180s).")
        return logs, findings
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao executar Amass: {exc}")
        return logs, findings

    subdomains: set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = entry.get("name")
        if name:
            subdomains.add(name.lower())

    log("info", f"Amass encontrou {len(subdomains)} subdomínio(s) único(s) via fontes passivas")

    interesting = sorted(s for s in subdomains if any(k in s for k in SENSITIVE_KEYWORDS))
    if interesting:
        log("warning", f"{len(interesting)} subdomínio(s) com nome potencialmente sensível: {', '.join(interesting[:10])}")
        findings.append(
            {
                "severity": "baixo",
                "title": f"{len(interesting)} subdomínio(s) com nome potencialmente sensível (via Amass)",
                "cwe": "CWE-200",
                "owasp_category": OWASP_MISCONFIG,
                "description": "Fontes públicas agregadas pelo Amass revelam subdomínios com nomes que sugerem ambientes de desenvolvimento, homologação ou administração: "
                + ", ".join(interesting[:30]),
                "impact": "Ambientes não-produtivos costumam ter controles de segurança mais fracos e podem expor dados/funcionalidades sensíveis se acessíveis publicamente.",
                "recommendation": "Revisar se cada subdomínio precisa ser publicamente resolvível/acessível; restringir por VPN, IP allowlist ou autenticação adicional quando não precisar estar público.",
                "reference_links": ["https://github.com/owasp-amass/amass"],
                "evidence": {"subdomains": interesting},
            }
        )

    findings.append(
        {
            "severity": "informativo",
            "title": f"{len(subdomains)} subdomínio(s) público(s) encontrados via Amass (modo passivo)",
            "cwe": None,
            "owasp_category": None,
            "description": f"Amass (-passive) agregando fontes públicas encontrou {len(subdomains)} nome(s) único(s) para {domain}.",
            "impact": "Mapeamento de superfície de ataque — não é uma vulnerabilidade por si só.",
            "recommendation": "Revisar a lista completa (nas evidências) e confirmar que todo subdomínio listado é intencional.",
            "reference_links": ["https://github.com/owasp-amass/amass"],
            "evidence": {"subdomains": sorted(subdomains)[:300]},
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
