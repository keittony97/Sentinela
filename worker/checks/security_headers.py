"""Verificação passiva de headers de segurança e certificado TLS.

Ferramenta "headers_tls": não intrusiva, só faz uma requisição GET normal
e inspeciona a resposta + o certificado — disponível em qualquer
modalidade legal (não é uma ferramenta ativa).
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

HEADER_CHECKS = [
    (
        "strict-transport-security",
        "medio",
        "HSTS (Strict-Transport-Security) ausente",
        "CWE-319",
        "Sem HSTS, o navegador pode ser induzido a acessar o site via HTTP, permitindo ataques de downgrade/man-in-the-middle.",
        "Adicione o header 'Strict-Transport-Security: max-age=31536000; includeSubDomains' nas respostas HTTPS.",
    ),
    (
        "content-security-policy",
        "medio",
        "Content-Security-Policy ausente",
        "CWE-1021",
        "Sem CSP, o navegador não tem uma política declarada para ajudar a bloquear XSS/injeção de scripts.",
        "Defina uma Content-Security-Policy restritiva adequada à aplicação.",
    ),
    (
        "x-content-type-options",
        "baixo",
        "X-Content-Type-Options ausente",
        "CWE-16",
        "Sem 'nosniff', navegadores podem tentar adivinhar o tipo de conteúdo, abrindo espaço para ataques de MIME-sniffing.",
        "Adicione o header 'X-Content-Type-Options: nosniff'.",
    ),
    (
        "x-frame-options",
        "baixo",
        "X-Frame-Options ausente",
        "CWE-1021",
        "Sem esse header (ou CSP frame-ancestors), a página pode ser embutida em um iframe malicioso (clickjacking).",
        "Adicione 'X-Frame-Options: DENY' ou 'Content-Security-Policy: frame-ancestors 'none''.",
    ),
    (
        "referrer-policy",
        "informativo",
        "Referrer-Policy ausente",
        "CWE-200",
        "Sem Referrer-Policy, a URL completa pode vazar para terceiros via cabeçalho Referer.",
        "Adicione 'Referrer-Policy: strict-origin-when-cross-origin' ou mais restritivo.",
    ),
]

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"


def run(url: str) -> tuple[list[dict], list[dict]]:
    """Executa a verificação. Retorna (linhas_de_log, findings)."""
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", f"Iniciando verificação de headers de segurança e TLS para {url}")

    parsed = urlparse(url)
    hostname = parsed.hostname
    is_https = parsed.scheme == "https"

    try:
        resp = httpx.get(url, follow_redirects=True, timeout=15)
        log("info", f"GET {url} -> HTTP {resp.status_code}")
    except Exception as exc:  # noqa: BLE001 - queremos capturar qualquer falha de rede
        log("error", f"Falha ao conectar: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível conectar ao alvo",
                "cwe": None,
                "owasp_category": None,
                "description": f"A tentativa de GET em {url} falhou: {exc}",
                "impact": "Não foi possível avaliar os headers de segurança pois a conexão falhou.",
                "recommendation": "Verifique se a URL está correta e acessível a partir do worker.",
                "reference_links": [],
                "evidence": {"url": url, "error": str(exc)},
            }
        )
        return logs, findings

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for header_name, severity, title, cwe, impact, recommendation in HEADER_CHECKS:
        if header_name in headers:
            log("info", f"OK: {header_name} presente ({headers[header_name][:80]})")
            continue

        log("warning", f"Header ausente: {header_name}")
        findings.append(
            {
                "severity": severity,
                "title": title,
                "cwe": cwe,
                "owasp_category": OWASP_MISCONFIG,
                "description": f"A resposta HTTP de {url} não inclui o header '{header_name}'.",
                "impact": impact,
                "recommendation": recommendation,
                "reference_links": ["https://owasp.org/www-project-secure-headers/"],
                "evidence": {
                    "url": url,
                    "status_code": resp.status_code,
                    "headers_present": sorted(headers.keys()),
                },
            }
        )

    server_header = headers.get("server")
    if server_header:
        log("warning", f"Header 'Server' expõe informação: {server_header}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Versão de servidor divulgada no header Server",
                "cwe": "CWE-200",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"O header 'Server' retornou: {server_header}",
                "impact": "Facilita o reconhecimento do atacante sobre a stack tecnológica usada.",
                "recommendation": "Configure o servidor/proxy para omitir ou generalizar o header 'Server'.",
                "reference_links": [],
                "evidence": {"server_header": server_header},
            }
        )

    if is_https and hostname:
        log("info", f"Verificando certificado TLS de {hostname}")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, parsed.port or 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (not_after - datetime.now(timezone.utc)).days
            log("info", f"Certificado válido até {not_after.isoformat()} ({days_left} dias restantes)")

            severity = None
            title = None
            if days_left < 0:
                severity, title = "critico", "Certificado TLS expirado"
            elif days_left < 15:
                severity, title = "alto", f"Certificado TLS expira em {days_left} dias"
            elif days_left < 30:
                severity, title = "medio", f"Certificado TLS expira em {days_left} dias"

            if severity:
                findings.append(
                    {
                        "severity": severity,
                        "title": title,
                        "cwe": "CWE-295",
                        "owasp_category": "A02:2021 - Cryptographic Failures",
                        "description": f"O certificado TLS de {hostname} expira em {not_after.isoformat()}.",
                        "impact": "Após expirar, navegadores bloqueiam o acesso e a comunicação deixa de ser autenticada/criptografada corretamente.",
                        "recommendation": "Renove o certificado TLS antes da expiração, idealmente com renovação automática (ex: Let's Encrypt + certbot).",
                        "reference_links": [],
                        "evidence": {"not_after": not_after.isoformat(), "days_left": days_left},
                    }
                )
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao verificar TLS: {exc}")

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
