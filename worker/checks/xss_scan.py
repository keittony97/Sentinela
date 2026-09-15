"""XSS ATIVO (refletido/armazenado) via Dalfox.

Ferramenta "xss_scan": ATIVA — dispara payloads reais de XSS (não só um
marcador inofensivo como 'basic_injection_probe') contra os parâmetros de
query da URL, usando Dalfox. Só disponível em projetos "Ambiente de
Teste" autorizados (Nível 1 — Detecção Ativa).
"""

import json
import shutil
import subprocess
from urllib.parse import parse_qs, urlparse

OWASP_INJECTION = "A03:2021 - Injection"


def _find_dalfox() -> str | None:
    return shutil.which("dalfox")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    params = parse_qs(urlparse(url).query)
    if not params:
        log("info", f"{url} não tem parâmetros de query — Dalfox precisa de ao menos um parâmetro pra testar.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Dalfox não executado — URL sem parâmetros de query",
                "cwe": None,
                "owasp_category": None,
                "description": f"A URL {url} não tem parâmetros (?chave=valor) para o Dalfox testar.",
                "impact": "Nenhum — esta ferramenta testa parâmetros de URL existentes.",
                "recommendation": "Se o alvo tiver endpoints/formulários com parâmetros em outras URLs, rodar apontando para essas URLs específicas.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    dalfox_binary = _find_dalfox()
    if not dalfox_binary:
        log("warning", "Dalfox não encontrado nesta máquina — verificação de XSS avançada pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação via Dalfox não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'xss_scan' precisa do binário 'dalfox' disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo. 'basic_injection_probe' já cobre uma checagem leve de XSS refletido.",
                "recommendation": "Instalar o Dalfox na máquina/container do worker (https://github.com/hahwul/dalfox) ou trocar por XSStrike.",
                "reference_links": ["https://github.com/hahwul/dalfox"],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log("info", f"Rodando Dalfox contra {url}")
    try:
        result = subprocess.run(
            [dalfox_binary, "url", url, "--silence", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log("error", "Dalfox excedeu o tempo limite (180s).")
        return logs, findings
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao executar Dalfox: {exc}")
        return logs, findings

    try:
        results = json.loads(result.stdout) if result.stdout.strip() else []
    except json.JSONDecodeError:
        log("warning", "Saída do Dalfox não é JSON válido — nenhum achado processado.")
        results = []

    if not isinstance(results, list):
        results = [results]

    vulnerable = [r for r in results if r.get("type") in ("V", "VULN") or r.get("severity")]
    log("info", f"Dalfox retornou {len(results)} resultado(s), {len(vulnerable)} classificado(s) como vulnerável")

    for r in vulnerable:
        param = r.get("param", "?")
        payload = r.get("payload", "")
        log("warning", f"XSS confirmado no parâmetro '{param}'")
        findings.append(
            {
                "severity": "alto",
                "title": f"XSS confirmado pelo Dalfox no parâmetro '{param}'",
                "cwe": "CWE-79",
                "owasp_category": OWASP_INJECTION,
                "description": f"Dalfox confirmou XSS no parâmetro '{param}' de {url} usando o payload: {payload[:200]}",
                "impact": "Um atacante pode injetar HTML/JavaScript arbitrário que roda no navegador de outros usuários (roubo de sessão, phishing, desfiguração da página).",
                "recommendation": f"Codificar (HTML-encode / usar Content Security Policy) o valor do parâmetro '{param}' antes de renderizá-lo.",
                "reference_links": ["https://owasp.org/www-community/attacks/xss/", "https://github.com/hahwul/dalfox"],
                "evidence": {"url": url, "param": param, "payload": payload, "raw": r},
            }
        )

    if not vulnerable:
        findings.append(
            {
                "severity": "informativo",
                "title": "Dalfox não confirmou XSS explorável",
                "cwe": None,
                "owasp_category": None,
                "description": f"Dalfox testou os parâmetros de {url} sem confirmar XSS explorável.",
                "impact": "Nenhum indício confirmado nesta verificação.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"url": url, "raw_results_count": len(results)},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
