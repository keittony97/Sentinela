"""Verificação passiva de segurança de cookies (Secure/HttpOnly/SameSite).

Ferramenta "cookie_security": só faz uma requisição GET normal e inspeciona
os cookies devolvidos — disponível em qualquer modalidade legal.
"""

from urllib.parse import urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"


def _parse_set_cookie_headers(resp: httpx.Response) -> list[str]:
    # httpx.Headers já junta múltiplos Set-Cookie corretamente via
    # get_list, ao contrário de headers.get() que só pega o primeiro.
    return resp.headers.get_list("set-cookie")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    is_https = urlparse(url).scheme == "https"
    log("info", f"Verificando cookies retornados por {url}")

    try:
        resp = httpx.get(url, follow_redirects=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao conectar: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível conectar ao alvo",
                "cwe": None,
                "owasp_category": None,
                "description": f"A tentativa de GET em {url} falhou: {exc}",
                "impact": "Não foi possível avaliar os cookies pois a conexão falhou.",
                "recommendation": "Verifique se a URL está correta e acessível a partir do worker.",
                "reference_links": [],
                "evidence": {"url": url, "error": str(exc)},
            }
        )
        return logs, findings

    cookies = _parse_set_cookie_headers(resp)
    if not cookies:
        log("info", "Nenhum cookie definido na resposta inicial — nada para avaliar aqui.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum cookie observado na resposta inicial",
                "cwe": None,
                "owasp_category": None,
                "description": f"A resposta de {url} não definiu nenhum cookie (Set-Cookie).",
                "impact": "Nenhum — a aplicação pode definir cookies só após login ou em outras rotas, não cobertas por esta requisição única.",
                "recommendation": "Se a aplicação usa sessão/autenticação, rodar esta verificação também numa URL pós-login.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log("info", f"{len(cookies)} cookie(s) encontrado(s) na resposta")

    for raw_cookie in cookies:
        name = raw_cookie.split("=", 1)[0].strip()
        lower = raw_cookie.lower()
        has_secure = "secure" in lower
        has_httponly = "httponly" in lower
        has_samesite = "samesite=" in lower
        samesite_value = None
        if has_samesite:
            for part in raw_cookie.split(";"):
                part = part.strip()
                if part.lower().startswith("samesite="):
                    samesite_value = part.split("=", 1)[1]

        missing = []
        if is_https and not has_secure:
            missing.append("Secure")
        if not has_httponly:
            missing.append("HttpOnly")
        if not has_samesite:
            missing.append("SameSite")

        if not missing:
            log("info", f"Cookie '{name}': Secure/HttpOnly/SameSite OK")
            continue

        log("warning", f"Cookie '{name}': faltando {', '.join(missing)}")
        severity = "medio" if "Secure" in missing or "HttpOnly" in missing else "baixo"
        findings.append(
            {
                "severity": severity,
                "title": f"Cookie '{name}' sem os atributos de segurança: {', '.join(missing)}",
                "cwe": "CWE-1004" if "HttpOnly" in missing else "CWE-614",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"O cookie '{name}' definido por {url} está sem: {', '.join(missing)}.",
                "impact": (
                    "Sem 'Secure', o cookie pode trafegar em texto claro por HTTP. "
                    "Sem 'HttpOnly', o cookie fica acessível via JavaScript (risco em caso de XSS). "
                    "Sem 'SameSite', o cookie é enviado em requisições cross-site (risco de CSRF)."
                ),
                "recommendation": f"Adicionar os atributos ausentes ({', '.join(missing)}) ao cookie '{name}' na resposta do servidor.",
                "reference_links": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                "evidence": {"cookie_name": name, "missing_attributes": missing, "samesite_value": samesite_value},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
