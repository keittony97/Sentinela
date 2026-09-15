"""Verificação de vazamento de e-mails corporativos via Have I Been Pwned.

Ferramenta "hibp_check": consulta a API pública do Have I Been Pwned para
endereços de e-mail comuns (info@, contato@, admin@...) do domínio do
alvo — nunca toca o alvo diretamente, só consulta um serviço de
terceiros. Disponível em qualquer modalidade legal.

A API v3 do HIBP exige uma chave paga (HIBP_API_KEY) desde 2024. Sem a
chave configurada, esta ferramenta registra um achado informativo em vez
de falhar (mesmo padrão já usado para outras integrações de terceiros
que dependem de API key, ex: o extinto exposed_ports.py via Shodan).
"""

import os
import time
from urllib.parse import urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_EXPOSURE = "A07:2021 - Identification and Authentication Failures"

TWO_LEVEL_TLDS = {"com.br", "net.br", "org.br", "gov.br", "co.uk", "org.uk", "com.au", "co.jp"}

# Prefixos de e-mail corporativo comuns o suficiente pra testar sem
# precisar de uma lista real de colaboradores (que a organização não nos
# fornece) — cobre PT-BR e EN.
COMMON_PREFIXES = [
    "info", "contact", "contato", "admin", "administrador",
    "support", "suporte", "sales", "comercial", "rh", "hr",
    "financeiro", "ti", "security", "seguranca",
]

HIBP_BREACHED_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


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

    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        log("warning", "HIBP_API_KEY não configurada — verificação de vazamento de e-mails pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação via Have I Been Pwned não executada (API key não configurada)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'hibp_check' precisa de HIBP_API_KEY configurada no ambiente do worker (chave paga da API v3 do HIBP).",
                "impact": "Nenhum — apenas informativo. Esta verificação simplesmente não rodou.",
                "recommendation": "Assinar uma chave de API em https://haveibeenpwned.com/API/Key e configurar HIBP_API_KEY no worker.",
                "reference_links": ["https://haveibeenpwned.com/API/Key"],
                "evidence": {"domain": domain},
            }
        )
        return logs, findings

    candidate_emails = [f"{prefix}@{domain}" for prefix in COMMON_PREFIXES]
    log("info", f"Consultando HIBP para {len(candidate_emails)} endereço(s) comum(ns) de {domain}")

    headers = {"hibp-api-key": api_key, "user-agent": "Sentinela-Pentest-Platform"}
    breached: list[dict] = []

    for email in candidate_emails:
        try:
            resp = httpx.get(
                HIBP_BREACHED_ACCOUNT_URL.format(account=email),
                params={"truncateResponse": "false"},
                headers=headers,
                timeout=15,
            )
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao consultar HIBP para {email}: {exc}")
            continue

        if resp.status_code == 200:
            breaches = resp.json()
            names = [b.get("Name", "?") for b in breaches]
            log("warning", f"{email}: encontrado em {len(breaches)} vazamento(s): {', '.join(names)}")
            breached.append({"email": email, "breaches": names})
        elif resp.status_code == 404:
            log("info", f"{email}: nenhum vazamento conhecido")
        elif resp.status_code == 429:
            log("warning", "Rate limit do HIBP atingido — aguardando antes de continuar")
            time.sleep(6)
        else:
            log("warning", f"{email}: HIBP retornou HTTP {resp.status_code}")

        # Respeita o rate limit da API (mínimo ~1 requisição a cada 1.5s
        # nos planos pagos do HIBP).
        time.sleep(1.6)

    if breached:
        findings.append(
            {
                "severity": "alto",
                "title": f"{len(breached)} e-mail(s) corporativo(s) encontrados em vazamentos conhecidos",
                "cwe": "CWE-200",
                "owasp_category": OWASP_EXPOSURE,
                "description": "Os seguintes endereços de e-mail corporativos (testados a partir de prefixos comuns) apareceram em vazamentos de dados conhecidos, segundo o Have I Been Pwned: "
                + "; ".join(f"{b['email']} ({', '.join(b['breaches'])})" for b in breached),
                "impact": "Credenciais associadas a esses e-mails podem ter vazado em texto claro ou hash quebrável em outros serviços — se a mesma senha for reutilizada internamente, isso facilita ataques de credential stuffing contra a organização.",
                "recommendation": "Forçar troca de senha das contas afetadas, habilitar MFA, e orientar os titulares a nunca reutilizar senhas entre serviços.",
                "reference_links": ["https://haveibeenpwned.com/"],
                "evidence": {"domain": domain, "breached_emails": breached},
            }
        )
    else:
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum e-mail corporativo comum encontrado em vazamentos conhecidos",
                "cwe": None,
                "owasp_category": None,
                "description": f"Nenhum dos {len(candidate_emails)} endereços testados (prefixos comuns @{domain}) apareceu em vazamentos conhecidos pelo HIBP.",
                "impact": "Nenhum indício encontrado — mas esta verificação só testa prefixos comuns, não a lista real de colaboradores da organização.",
                "recommendation": "Para uma cobertura completa, verificar manualmente os e-mails reais de colaboradores em https://haveibeenpwned.com/.",
                "reference_links": ["https://haveibeenpwned.com/"],
                "evidence": {"domain": domain, "candidates_tested": len(candidate_emails)},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
