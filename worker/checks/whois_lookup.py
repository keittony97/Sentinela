"""Verificação passiva de WHOIS (expiração e servidores de nome do domínio).

Ferramenta "whois_lookup": consulta o serviço público de WHOIS do
registrador/TLD — não toca o alvo diretamente. Disponível em qualquer
modalidade legal.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

import whois as whois_lib

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"

TWO_LEVEL_TLDS = {"com.br", "net.br", "org.br", "gov.br", "co.uk", "org.uk", "com.au", "co.jp"}


def _apex_domain(hostname: str) -> str:
    labels = hostname.lower().split(".")
    if len(labels) <= 2:
        return hostname.lower()
    last_two = ".".join(labels[-2:])
    if last_two in TWO_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def _first(value):
    """python-whois às vezes devolve uma data única, às vezes uma lista de datas."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


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
    log("info", f"Consultando WHOIS de {domain}")

    try:
        record = whois_lib.whois(domain)
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao consultar WHOIS: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível consultar o WHOIS do domínio",
                "cwe": None,
                "owasp_category": None,
                "description": f"A consulta WHOIS para {domain} falhou: {exc}",
                "impact": "Não foi possível confirmar expiração/servidores de nome por essa via.",
                "recommendation": "Consultar manualmente o WHOIS do domínio junto ao registrador.",
                "reference_links": [],
                "evidence": {"domain": domain, "error": str(exc)},
            }
        )
        return logs, findings

    expiration = _first(getattr(record, "expiration_date", None))
    nameservers = record.name_servers or []
    registrar = record.registrar

    log("info", f"Registrador: {registrar or 'desconhecido'}")
    log("info", f"Servidores de nome: {', '.join(nameservers) if nameservers else 'nenhum retornado'}")

    if expiration:
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=timezone.utc)
        days_left = (expiration - datetime.now(timezone.utc)).days
        log("info", f"Domínio expira em {expiration.date().isoformat()} ({days_left} dias restantes)")

        severity = None
        title = None
        if days_left < 0:
            severity, title = "critico", "Domínio expirado"
        elif days_left < 15:
            severity, title = "alto", f"Domínio expira em {days_left} dias"
        elif days_left < 30:
            severity, title = "medio", f"Domínio expira em {days_left} dias"

        if severity:
            findings.append(
                {
                    "severity": severity,
                    "title": title,
                    "cwe": "CWE-1390",
                    "owasp_category": OWASP_MISCONFIG,
                    "description": f"O domínio {domain} expira em {expiration.date().isoformat()}, segundo o WHOIS.",
                    "impact": "Se o domínio expirar, ele fica sujeito a sequestro por terceiros (domain hijacking) — inclusive com risco de continuar recebendo tráfego/e-mail em nome da organização em mãos erradas.",
                    "recommendation": "Renovar o domínio imediatamente, idealmente configurando renovação automática junto ao registrador.",
                    "reference_links": [],
                    "evidence": {"domain": domain, "expiration_date": expiration.isoformat(), "days_left": days_left},
                }
            )
    else:
        log("warning", "WHOIS não retornou data de expiração (comum em alguns ccTLDs que restringem esse dado).")

    findings.append(
        {
            "severity": "informativo",
            "title": "Dados de WHOIS do domínio",
            "cwe": None,
            "owasp_category": None,
            "description": f"Registrador: {registrar or 'desconhecido'}. Servidores de nome: {', '.join(nameservers) if nameservers else 'nenhum'}.",
            "impact": "Informativo — mapeia quem administra o domínio.",
            "recommendation": "Confirmar que o registrador e os servidores de nome são os esperados pela organização.",
            "reference_links": [],
            "evidence": {
                "domain": domain,
                "registrar": registrar,
                "name_servers": nameservers,
                "expiration_date": expiration.isoformat() if expiration else None,
            },
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
