"""Varredura ATIVA de configuração insegura de GraphQL.

Ferramenta "graphql_scan": ATIVA — só faz sentido se o alvo expõe um
endpoint GraphQL; esta ferramenta primeiro tenta descobrir um
automaticamente em caminhos comuns, e então dispara consultas GraphQL
reais (introspection, batching) contra ele. Implementado em Python puro
em vez de depender do binário "GraphQL Cop" — o pacote publicado com
esse nome no PyPI é só um placeholder reservado sem funcionalidade (dolevf/
graphql-cop, o projeto real, só existe como script no GitHub, não como
pacote instalável) — as checagens abaixo cobrem o mesmo escopo descrito
em CLAUDE.md: introspection habilitada e batching abuse. Só disponível
em projetos "Ambiente de Teste" autorizados (Nível 1 — Detecção Ativa).
"""

from urllib.parse import urljoin

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_MISCONFIG = "A05:2021 - Security Misconfiguration"

COMMON_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql", "/query"]

INTROSPECTION_QUERY = {
    "query": "query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"
}

BATCH_QUERY = [{"query": "{ __typename }"} for _ in range(25)]


def _looks_like_graphql_response(resp: httpx.Response) -> bool:
    if resp.status_code >= 500:
        return False
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return False
    return isinstance(data, dict) and ("data" in data or "errors" in data)


def _discover_endpoint(base_url: str, log) -> str | None:
    for path in COMMON_GRAPHQL_PATHS:
        candidate = urljoin(base_url, path)
        try:
            resp = httpx.post(candidate, json={"query": "{ __typename }"}, timeout=10, follow_redirects=True)
        except Exception:  # noqa: BLE001
            continue
        if _looks_like_graphql_response(resp):
            log("info", f"Endpoint GraphQL encontrado em {candidate}")
            return candidate
    return None


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", f"Procurando endpoint GraphQL em caminhos comuns de {url}")
    endpoint = _discover_endpoint(url, log)

    if not endpoint:
        log("info", "Nenhum endpoint GraphQL encontrado nos caminhos comuns testados.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Varredura de GraphQL não aplicável — nenhum endpoint encontrado",
                "cwe": None,
                "owasp_category": None,
                "description": f"Testados {len(COMMON_GRAPHQL_PATHS)} caminhos comuns a partir de {url} sem encontrar um endpoint GraphQL.",
                "impact": "Nenhum — esta ferramenta depende de um endpoint GraphQL descoberto automaticamente.",
                "recommendation": "Se a API GraphQL estiver em um caminho não padrão, informar a URL exata manualmente.",
                "reference_links": [],
                "evidence": {"paths_tested": COMMON_GRAPHQL_PATHS},
            }
        )
        return logs, findings

    # --- Introspection habilitada ---
    try:
        resp = httpx.post(endpoint, json=INTROSPECTION_QUERY, timeout=15)
        data = resp.json()
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao testar introspection: {exc}")
        data = {}

    types = data.get("data", {}).get("__schema", {}).get("types", []) if isinstance(data, dict) else []
    if types:
        log("warning", f"Introspection GraphQL HABILITADA — {len(types)} tipo(s) do schema expostos.")
        findings.append(
            {
                "severity": "medio",
                "title": "Introspection GraphQL habilitada em produção",
                "cwe": "CWE-200",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"O endpoint {endpoint} responde a queries de introspection, expondo {len(types)} tipo(s) do schema completo (nomes de campos, mutations, tipos internos).",
                "impact": "Um atacante pode mapear toda a API (campos, mutations, relacionamentos) sem precisar de documentação, facilitando a descoberta de funcionalidades sensíveis ou mal protegidas.",
                "recommendation": "Desabilitar introspection em produção (a maioria dos frameworks GraphQL tem uma flag para isso), mantendo habilitada só em ambientes de desenvolvimento.",
                "reference_links": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
                "evidence": {"endpoint": endpoint, "types_count": len(types)},
            }
        )
    else:
        log("info", "Introspection GraphQL não habilitada (ou bloqueada).")
        findings.append(
            {
                "severity": "informativo",
                "title": "Introspection GraphQL desabilitada",
                "cwe": None,
                "owasp_category": None,
                "description": f"O endpoint {endpoint} não respondeu à query de introspection com o schema completo.",
                "impact": "Nenhum — comportamento esperado em produção.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"endpoint": endpoint},
            }
        )

    # --- Batching abuse: múltiplas queries num único array JSON ---
    try:
        batch_resp = httpx.post(endpoint, json=BATCH_QUERY, timeout=15)
        batch_data = batch_resp.json()
        batch_accepted = isinstance(batch_data, list) and len(batch_data) == len(BATCH_QUERY)
    except Exception as exc:  # noqa: BLE001
        log("info", f"Não foi possível testar batching: {exc}")
        batch_accepted = False

    if batch_accepted:
        log("warning", f"Endpoint aceita batching sem limite aparente ({len(BATCH_QUERY)} queries num único request)")
        findings.append(
            {
                "severity": "medio",
                "title": "GraphQL aceita batching de queries sem limite aparente",
                "cwe": "CWE-770",
                "owasp_category": OWASP_MISCONFIG,
                "description": f"O endpoint {endpoint} processou um array com {len(BATCH_QUERY)} queries num único request HTTP sem rejeitar por excesso.",
                "impact": "Batching sem limite permite contornar rate-limiting por requisição (ex: testar centenas de tentativas de login/OTP num único POST) e amplifica ataques de negação de serviço.",
                "recommendation": "Limitar o número de operações por batch (ou desabilitar batching) e aplicar rate-limiting por operação individual, não só por requisição HTTP.",
                "reference_links": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
                "evidence": {"endpoint": endpoint, "batch_size_tested": len(BATCH_QUERY)},
            }
        )
    else:
        log("info", "Endpoint não aceita batching sem limite (ou não suporta batching).")

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
