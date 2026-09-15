"""Verificação passiva de configuração de CORS.

Ferramenta "cors_config": envia requisições HTTP padrão (GET normal + uma
requisição com o header 'Origin' de um domínio arbitrário — o mesmo que
qualquer navegador cross-origin faria) e inspeciona os headers de resposta
'Access-Control-Allow-*'. Não explora nada, não envia payload. Disponível
em qualquer modalidade legal.
"""

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"
PROBE_ORIGIN = "https://sentinela-cors-probe.invalid"


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", f"Testando configuração de CORS em {url} com Origin arbitrária ({PROBE_ORIGIN})")

    try:
        resp = httpx.get(
            url,
            headers={"Origin": PROBE_ORIGIN},
            follow_redirects=True,
            timeout=15,
        )
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao conectar: {exc}")
        findings.append(
            {
                "severity": "informativo",
                "title": "Não foi possível conectar ao alvo",
                "cwe": None,
                "owasp_category": None,
                "description": f"A tentativa de GET em {url} falhou: {exc}",
                "impact": "Não foi possível avaliar a configuração de CORS pois a conexão falhou.",
                "recommendation": "Verifique se a URL está correta e acessível a partir do worker.",
                "reference_links": [],
                "evidence": {"url": url, "error": str(exc)},
            }
        )
        return logs, findings

    headers = {k.lower(): v for k, v in resp.headers.items()}
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower() == "true"

    if not acao:
        log("info", "Nenhum header Access-Control-Allow-Origin retornado — CORS não habilitado para esta rota.")
        findings.append(
            {
                "severity": "informativo",
                "title": "CORS não habilitado nesta rota",
                "cwe": None,
                "owasp_category": None,
                "description": f"{url} não retornou 'Access-Control-Allow-Origin' mesmo enviando um header Origin.",
                "impact": "Nenhum — esta rota não expõe dados via CORS (ou exige um método/header diferente para habilitar).",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log("info", f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {acac}")

    if acao == "*" and acac:
        # Isso é tecnicamente inválido pela spec (navegadores rejeitam
        # '*' junto com credentials=true), mas indica configuração
        # confusa/perigosa que pode falhar de forma insegura em algum
        # cliente ou proxy.
        log("warning", "CORS: '*' combinado com Allow-Credentials: true — configuração inválida e perigosa.")
        findings.append(
            {
                "severity": "alto",
                "title": "CORS permite qualquer origem (*) junto com credenciais",
                "cwe": "CWE-942",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"{url} retorna 'Access-Control-Allow-Origin: *' e 'Access-Control-Allow-Credentials: true' simultaneamente.",
                "impact": "Configuração contraditória que sugere uma implementação manual/insegura de CORS — risco real se algum cliente HTTP não navegador (ou uma versão de navegador mais permissiva) aceitar essa combinação, expondo dados autenticados a qualquer origem.",
                "recommendation": "Nunca combinar '*' com credentials=true. Definir uma allowlist explícita de origens confiáveis.",
                "reference_links": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                "evidence": {"url": url, "access_control_allow_origin": acao, "access_control_allow_credentials": acac},
            }
        )
    elif acao == PROBE_ORIGIN and acac:
        log("warning", f"CORS reflete QUALQUER Origin ({PROBE_ORIGIN}) e permite credenciais — vulnerável.")
        findings.append(
            {
                "severity": "critico",
                "title": "CORS reflete qualquer Origin e permite credenciais",
                "cwe": "CWE-942",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"{url} refletiu a Origin arbitrária enviada ({PROBE_ORIGIN}) em 'Access-Control-Allow-Origin' e retornou 'Access-Control-Allow-Credentials: true'.",
                "impact": "Qualquer site malicioso pode fazer requisições autenticadas (com cookies/sessão da vítima) a este endpoint e ler a resposta — permite roubo de dados de sessão/conta de qualquer usuário que visite o site atacante.",
                "recommendation": "Nunca refletir a Origin recebida sem validá-la contra uma allowlist explícita de domínios confiáveis, especialmente quando 'Allow-Credentials: true' está habilitado.",
                "reference_links": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                "evidence": {"url": url, "probe_origin": PROBE_ORIGIN, "reflected": True},
            }
        )
    elif acao == PROBE_ORIGIN:
        log("warning", f"CORS reflete qualquer Origin ({PROBE_ORIGIN}) sem exigir allowlist (sem credenciais).")
        findings.append(
            {
                "severity": "medio",
                "title": "CORS reflete qualquer Origin recebida",
                "cwe": "CWE-942",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"{url} refletiu a Origin arbitrária enviada ({PROBE_ORIGIN}) em 'Access-Control-Allow-Origin', sem 'Allow-Credentials'.",
                "impact": "Qualquer site pode ler respostas públicas deste endpoint via JavaScript cross-origin — menos grave sem credenciais, mas ainda indica ausência de allowlist.",
                "recommendation": "Validar a Origin recebida contra uma allowlist explícita de domínios confiáveis, mesmo para endpoints sem dados sensíveis.",
                "reference_links": ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                "evidence": {"url": url, "probe_origin": PROBE_ORIGIN, "reflected": True},
            }
        )
    else:
        log("info", f"CORS restrito a uma origem fixa/allowlist ({acao}) — não reflete a Origin de teste.")
        findings.append(
            {
                "severity": "informativo",
                "title": "CORS configurado com origem(ns) fixa(s)",
                "cwe": None,
                "owasp_category": None,
                "description": f"{url} retorna 'Access-Control-Allow-Origin: {acao}', que não corresponde à Origin arbitrária de teste.",
                "impact": "Nenhum indício de má configuração nesta verificação.",
                "recommendation": "Confirmar que a lista de origens permitidas está atualizada e restrita ao necessário.",
                "reference_links": [],
                "evidence": {"url": url, "access_control_allow_origin": acao},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
