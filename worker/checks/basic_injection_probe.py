"""Sonda ATIVA de injeção (XSS refletido / SQLi baseado em erro).

Ferramenta "basic_injection_probe": ATIVA — só roda em projetos na
modalidade "Ambiente de Teste" com autorização confirmada, disparada só
por Admin (gate reforçado no banco via enforce_scan_legal_mode, não só
na UI). Envia um marcador inofensivo e uma aspas simples nos parâmetros
de query já existentes na URL — não explora nada de verdade (sem UNION
SELECT, sem blind/time-based, sem brute-force), só testa se o input
volta sem escape HTML ou quebra uma query SQL o suficiente pra vazar uma
mensagem de erro do banco.
"""

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

XSS_MARKER_VALUE = "sntnl_probe_<b>9f8a3c</b>"
XSS_MARKER_NEEDLE = "<b>9f8a3c</b>"

SQLI_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql_fetch",
    r"you have an error in your sql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{5}",
    r"sqlite3?\.\w*error",
    r"postgresql.*error",
    r"pg_query\(\)",
    r"warning: pg_",
    r"odbc sql server driver",
    r"microsoft ole db provider",
]

OWASP_INJECTION = "A03:2021 - Injection"


def _build_url_with_param(base_url: str, params: dict[str, list[str]], key: str, value: str) -> str:
    parsed = urlparse(base_url)
    new_params = {k: list(v) for k, v in params.items()}
    new_params[key] = [value]
    query = urlencode(new_params, doseq=True)
    return urlunparse(parsed._replace(query=query))


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        log("info", f"{url} não tem parâmetros de query — nada para testar com esta sonda.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Sonda de injeção não encontrou parâmetros para testar",
                "cwe": None,
                "owasp_category": None,
                "description": f"A URL {url} não tem parâmetros de query (?chave=valor).",
                "impact": "Nenhum — esta sonda só testa parâmetros de URL existentes.",
                "recommendation": "Se o alvo tiver formulários ou endpoints com parâmetros em outras URLs, rode a verificação apontando para essas URLs específicas.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log("info", f"Testando {len(params)} parâmetro(s) de query em {url}")

    try:
        baseline = httpx.get(url, timeout=15, follow_redirects=True)
        log("info", f"Baseline: HTTP {baseline.status_code}, {len(baseline.content)} bytes")
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao obter baseline: {exc}")
        return logs, findings

    for key in params:
        # --- XSS refletido: o marcador tem que voltar SEM escape HTML ---
        xss_url = _build_url_with_param(url, params, key, XSS_MARKER_VALUE)
        try:
            resp = httpx.get(xss_url, timeout=15, follow_redirects=True)
            if XSS_MARKER_NEEDLE in resp.text:
                log("warning", f"Parâmetro '{key}': marcador refletido sem escape HTML — possível XSS refletido")
                findings.append(
                    {
                        "severity": "alto",
                        "title": f"Possível XSS refletido no parâmetro '{key}'",
                        "cwe": "CWE-79",
                        "owasp_category": OWASP_INJECTION,
                        "description": f"Um marcador com tags HTML foi enviado no parâmetro '{key}' de {url} e voltou sem escape na resposta.",
                        "impact": "Um atacante pode injetar HTML/JavaScript arbitrário que roda no navegador de outros usuários (roubo de sessão, phishing, desfiguração da página).",
                        "recommendation": f"Codificar (HTML-encode) o valor do parâmetro '{key}' antes de renderizá-lo, ou usar um template engine com escaping automático.",
                        "reference_links": ["https://owasp.org/www-community/attacks/xss/"],
                        "evidence": {"url": xss_url, "param": key, "marker": XSS_MARKER_VALUE},
                    }
                )
            else:
                log("info", f"Parâmetro '{key}': marcador XSS não refletido sem escape (ok)")
        except Exception as exc:  # noqa: BLE001
            log("error", f"Parâmetro '{key}' (XSS): falha na requisição ({exc})")

        # --- SQLi baseado em erro: uma aspas simples costuma quebrar query mal escrita ---
        original_value = params[key][0] if params[key] else ""
        sqli_url = _build_url_with_param(url, params, key, original_value + "'")
        try:
            resp = httpx.get(sqli_url, timeout=15, follow_redirects=True)
            body_lower = resp.text.lower()
            matched_pattern = next((p for p in SQLI_ERROR_PATTERNS if re.search(p, body_lower)), None)

            if matched_pattern:
                log(
                    "warning",
                    f"Parâmetro '{key}': resposta contém padrão de erro de banco de dados após injetar aspas simples",
                )
                findings.append(
                    {
                        "severity": "critico",
                        "title": f"Possível SQL Injection no parâmetro '{key}' (baseado em erro)",
                        "cwe": "CWE-89",
                        "owasp_category": OWASP_INJECTION,
                        "description": f"Adicionar uma aspas simples (') ao parâmetro '{key}' de {url} produziu uma resposta com padrão de mensagem de erro de banco de dados.",
                        "impact": "Um atacante pode manipular consultas SQL para ler, alterar ou apagar dados do banco, ou contornar autenticação.",
                        "recommendation": f"Usar consultas parametrizadas (prepared statements) para o parâmetro '{key}' em vez de concatenar a entrada diretamente na query SQL.",
                        "reference_links": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                        "evidence": {"url": sqli_url, "param": key, "matched_pattern": matched_pattern},
                    }
                )
            elif resp.status_code >= 500 and baseline.status_code < 500:
                log(
                    "warning",
                    f"Parâmetro '{key}': aspas simples causou HTTP {resp.status_code} (baseline era {baseline.status_code})",
                )
                findings.append(
                    {
                        "severity": "medio",
                        "title": f"Parâmetro '{key}' causa erro do servidor com entrada não usual",
                        "cwe": "CWE-20",
                        "owasp_category": OWASP_INJECTION,
                        "description": f"Adicionar uma aspas simples (') ao parâmetro '{key}' mudou o status de {baseline.status_code} para {resp.status_code}.",
                        "impact": "Pode indicar falta de tratamento/validação de entrada — não confirma SQLi por si só, mas merece investigação manual.",
                        "recommendation": f"Investigar manualmente o comportamento do parâmetro '{key}' com caracteres especiais e garantir tratamento de erro adequado.",
                        "reference_links": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                        "evidence": {
                            "url": sqli_url,
                            "param": key,
                            "status_code": resp.status_code,
                            "baseline_status": baseline.status_code,
                        },
                    }
                )
            else:
                log("info", f"Parâmetro '{key}': sem indício de SQLi baseado em erro")
        except Exception as exc:  # noqa: BLE001
            log("error", f"Parâmetro '{key}' (SQLi): falha na requisição ({exc})")

    log("info", f"Sonda concluída: {len(findings)} achado(s).")
    return logs, findings
