"""Verificação passiva de HSTS/preload, redirecionamento HTTP→HTTPS e mixed content.

Ferramenta "hsts_mixed_content": só faz requisições HTTP/HTTPS padrão (o
mesmo que um navegador faria) — disponível em qualquer modalidade legal.
Complementa "headers_tls" (que só checa a presença do header HSTS): aqui
avaliamos as diretivas do HSTS, o comportamento real do redirecionamento
HTTP->HTTPS, e referências a recursos HTTP numa página HTTPS.
"""

import re
from urllib.parse import urlparse, urlunparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"

# Atributos que costumam carregar sub-recursos: src (script/img/iframe/
# audio/video), href (link rel=stylesheet).
MIXED_CONTENT_PATTERN = re.compile(
    r"""(?:src|href)\s*=\s*["']http://[^"']+["']""", re.IGNORECASE
)


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    parsed = urlparse(url)
    if parsed.scheme != "https":
        log("info", f"{url} não é HTTPS — verificação de HSTS/mixed content não se aplica.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação de HSTS/mixed content não aplicável (alvo não é HTTPS)",
                "cwe": None,
                "owasp_category": None,
                "description": f"A URL cadastrada ({url}) usa o esquema '{parsed.scheme}', não 'https'.",
                "impact": "Nenhum — esta verificação só se aplica a alvos HTTPS.",
                "recommendation": "Se o alvo deveria estar em HTTPS, cadastrar a URL com o esquema correto.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    # --- Redirecionamento HTTP -> HTTPS ---
    http_url = urlunparse(parsed._replace(scheme="http"))
    log("info", f"Testando se {http_url} redireciona para HTTPS")
    try:
        resp_http = httpx.get(http_url, follow_redirects=False, timeout=15)
        if 300 <= resp_http.status_code < 400:
            location = resp_http.headers.get("location", "")
            if location.startswith("https://"):
                log("info", f"HTTP redireciona para HTTPS corretamente ({resp_http.status_code} -> {location})")
            else:
                log("warning", f"HTTP redireciona, mas não para HTTPS: {location}")
                findings.append(
                    {
                        "severity": "alto",
                        "title": "Redirecionamento HTTP não aponta para HTTPS",
                        "cwe": "CWE-319",
                        "owasp_category": OWASP_MISCONFIG,
                        "description": f"{http_url} redireciona ({resp_http.status_code}) para '{location}', que não é HTTPS.",
                        "impact": "Usuários que acessam via HTTP continuam trafegando dados sem criptografia.",
                        "recommendation": "Configurar o redirecionamento de HTTP para apontar sempre para a versão HTTPS equivalente.",
                        "reference_links": [],
                        "evidence": {"http_url": http_url, "status_code": resp_http.status_code, "location": location},
                    }
                )
        else:
            log("warning", f"HTTP não redireciona para HTTPS (HTTP {resp_http.status_code})")
            findings.append(
                {
                    "severity": "alto",
                    "title": "Acesso via HTTP não redireciona para HTTPS",
                    "cwe": "CWE-319",
                    "owasp_category": OWASP_MISCONFIG,
                    "description": f"{http_url} respondeu HTTP {resp_http.status_code} em vez de redirecionar para HTTPS.",
                    "impact": "Usuários que acessam via HTTP (ex: digitando o domínio sem 'https://') trafegam dados sem criptografia, sujeitos a interceptação/adulteração.",
                    "recommendation": "Configurar o servidor/proxy para redirecionar (301/308) toda requisição HTTP para a versão HTTPS.",
                    "reference_links": [],
                    "evidence": {"http_url": http_url, "status_code": resp_http.status_code},
                }
            )
    except Exception as exc:  # noqa: BLE001
        log("info", f"Não foi possível testar a versão HTTP ({exc}) — pode já estar bloqueada, o que é aceitável.")

    # --- HSTS: diretivas (max-age, includeSubDomains, preload) ---
    try:
        resp_https = httpx.get(url, follow_redirects=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao conectar via HTTPS: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível conectar ao alvo via HTTPS",
                "cwe": None,
                "owasp_category": None,
                "description": f"A tentativa de GET em {url} falhou: {exc}",
                "impact": "Não foi possível avaliar HSTS/mixed content pois a conexão falhou.",
                "recommendation": "Verifique se a URL está correta e acessível a partir do worker.",
                "reference_links": [],
                "evidence": {"url": url, "error": str(exc)},
            }
        )
        return logs, findings

    hsts = resp_https.headers.get("strict-transport-security")
    if hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_subdomains = "includesubdomains" in hsts.lower()
        has_preload = "preload" in hsts.lower()
        log("info", f"HSTS presente: {hsts}")

        if max_age < 31536000:  # menos de 1 ano
            log("warning", f"HSTS max-age curto: {max_age}s (recomendado >= 31536000, 1 ano)")
            findings.append(
                {
                    "severity": "baixo",
                    "title": f"HSTS com max-age curto ({max_age}s)",
                    "cwe": "CWE-319",
                    "owasp_category": OWASP_MISCONFIG,
                    "description": f"O header HSTS de {url} tem max-age={max_age}, abaixo de 1 ano (31536000s).",
                    "impact": "Um max-age curto reduz a janela de proteção contra downgrade para HTTP entre visitas do usuário.",
                    "recommendation": "Aumentar max-age para pelo menos 31536000 (1 ano), com includeSubDomains e, se aplicável, preload.",
                    "reference_links": ["https://hstspreload.org/"],
                    "evidence": {"url": url, "hsts_header": hsts, "max_age": max_age},
                }
            )
        if not has_preload:
            log("info", "HSTS sem diretiva 'preload' — não elegível para a lista de preload dos navegadores.")
            findings.append(
                {
                    "severity": "informativo",
                    "title": "HSTS sem diretiva 'preload'",
                    "cwe": None,
                    "owasp_category": None,
                    "description": f"O header HSTS de {url} não inclui 'preload'.",
                    "impact": "Sem 'preload', a proteção HSTS só vale a partir da primeira visita — a primeira conexão ainda pode ser interceptada (trust on first use).",
                    "recommendation": "Se fizer sentido para o domínio, adicionar 'preload' ao HSTS (com max-age>=1 ano e includeSubDomains) e submeter em hstspreload.org.",
                    "reference_links": ["https://hstspreload.org/"],
                    "evidence": {"url": url, "hsts_header": hsts},
                }
            )
        if not has_subdomains:
            log("info", "HSTS sem 'includeSubDomains'.")
    else:
        log("info", "HSTS ausente (já reportado por 'headers_tls', não duplicado aqui).")

    # --- Mixed content: referências a recursos HTTP numa página HTTPS ---
    matches = MIXED_CONTENT_PATTERN.findall(resp_https.text)
    if matches:
        sample = matches[:10]
        log("warning", f"{len(matches)} referência(s) a recursos HTTP encontradas numa página HTTPS")
        findings.append(
            {
                "severity": "medio",
                "title": f"{len(matches)} referência(s) a conteúdo HTTP (mixed content) em página HTTPS",
                "cwe": "CWE-319",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"A página {url} (servida via HTTPS) contém {len(matches)} referência(s) a recursos carregados via HTTP simples.",
                "impact": "Recursos carregados via HTTP numa página HTTPS podem ser interceptados/adulterados em trânsito (ex: um script HTTP modificado por um atacante man-in-the-middle), e navegadores modernos costumam bloquear ou avisar sobre isso.",
                "recommendation": "Atualizar todas as referências para usar HTTPS (ou URLs relativas ao protocolo).",
                "reference_links": ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
                "evidence": {"url": url, "sample_matches": sample, "total": len(matches)},
            }
        )
    else:
        log("info", "Nenhuma referência a recurso HTTP encontrada no HTML.")

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
