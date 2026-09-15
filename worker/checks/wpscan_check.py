"""Scanner ATIVO específico de WordPress via WPScan.

Ferramenta "wpscan_check": ATIVA — só faz sentido rodar contra alvos
WordPress; esta ferramenta primeiro confirma isso com uma checagem leve
própria (não depende de 'tech_fingerprint' já ter rodado no mesmo scan) e
só então dispara o WPScan de verdade (enumeração de plugins/temas/
usuários, checagem contra vulnerabilidades conhecidas). Só disponível em
projetos "Ambiente de Teste" autorizados (Nível 1 — Detecção Ativa).
"""

import json
import os
import shutil
import subprocess

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

OWASP_VULN_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"


def _looks_like_wordpress(url: str, log) -> bool:
    try:
        resp = httpx.get(url, follow_redirects=True, timeout=15)
    except Exception as exc:  # noqa: BLE001
        log("warning", f"Falha ao confirmar se é WordPress: {exc}")
        return False
    body = resp.text
    return "wp-content" in body or "wp-includes" in body or "/wp-json/" in body


def _find_wpscan() -> str | None:
    return shutil.which("wpscan")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    log("info", f"Confirmando se {url} é WordPress antes de rodar WPScan")
    if not _looks_like_wordpress(url, log):
        log("info", "Alvo não parece ser WordPress (sem sinais de wp-content/wp-includes/wp-json) — WPScan pulado.")
        findings.append(
            {
                "severity": "informativo",
                "title": "WPScan não executado — alvo não parece ser WordPress",
                "cwe": None,
                "owasp_category": None,
                "description": f"{url} não apresenta sinais de WordPress (wp-content, wp-includes, /wp-json/) no HTML público.",
                "impact": "Nenhum — esta ferramenta só se aplica a alvos WordPress.",
                "recommendation": "Nenhuma ação necessária.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log("info", "Alvo confirmado como WordPress.")

    wpscan_binary = _find_wpscan()
    if not wpscan_binary:
        log("warning", "WPScan não encontrado nesta máquina — verificação pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "WPScan não executado (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'wpscan_check' precisa do binário 'wpscan' disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo. O alvo foi confirmado como WordPress, mas o scanner específico não rodou.",
                "recommendation": "Instalar o WPScan na máquina/container do worker (`gem install wpscan`) e, opcionalmente, configurar WPSCAN_API_TOKEN para checar contra o banco de vulnerabilidades da WPScan.",
                "reference_links": ["https://wpscan.com/"],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    api_token = os.environ.get("WPSCAN_API_TOKEN")
    cmd = [wpscan_binary, "--url", url, "--format", "json", "--no-banner", "--random-user-agent"]
    if api_token:
        cmd += ["--api-token", api_token]
    else:
        log("warning", "WPSCAN_API_TOKEN não configurado — enumeração roda, mas sem checagem contra o banco de CVEs da WPScan.")

    log("info", "Rodando WPScan (enumeração de plugins, temas e usuários)")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        log("error", "WPScan excedeu o tempo limite (300s).")
        return logs, findings
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao executar WPScan: {exc}")
        return logs, findings

    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        log("error", "Saída do WPScan não é JSON válido.")
        return logs, findings

    version_info = data.get("version", {}) or {}
    wp_version = version_info.get("number")
    if wp_version:
        log("info", f"Versão do WordPress detectada: {wp_version}")

    plugins = data.get("plugins", {}) or {}
    vulnerable_plugins = {
        name: info for name, info in plugins.items() if info.get("vulnerabilities")
    }
    for name, info in vulnerable_plugins.items():
        vulns = info.get("vulnerabilities", [])
        titles = [v.get("title", "?") for v in vulns]
        log("warning", f"Plugin '{name}' com {len(vulns)} vulnerabilidade(s) conhecida(s)")
        findings.append(
            {
                "severity": "alto",
                "title": f"Plugin WordPress vulnerável: {name}",
                "cwe": "CWE-1104",
                "owasp_category": OWASP_VULN_COMPONENTS,
                "description": f"O plugin '{name}' (versão {info.get('version', {}).get('number', '?')}) tem vulnerabilidade(s) conhecida(s): {', '.join(titles)}.",
                "impact": "Plugins desatualizados/vulneráveis são um dos vetores mais comuns de comprometimento de sites WordPress.",
                "recommendation": f"Atualizar o plugin '{name}' para a versão mais recente ou removê-lo se não for essencial.",
                "reference_links": ["https://wpscan.com/"],
                "evidence": {"plugin": name, "version": info.get("version"), "vulnerabilities": titles},
            }
        )

    users = data.get("users", {}) or {}
    if users:
        usernames = list(users.keys())
        log("warning", f"{len(usernames)} usuário(s) WordPress enumerado(s): {', '.join(usernames)}")
        findings.append(
            {
                "severity": "baixo",
                "title": f"{len(usernames)} nome(s) de usuário WordPress enumerável(is)",
                "cwe": "CWE-200",
                "owasp_category": "A07:2021 - Identification and Authentication Failures",
                "description": f"WPScan conseguiu enumerar os seguintes nomes de usuário: {', '.join(usernames)}.",
                "impact": "Nomes de usuário válidos facilitam ataques de força bruta/credential stuffing direcionados.",
                "recommendation": "Desabilitar a enumeração de usuários via REST API/author archive, e usar nomes de exibição diferentes do login.",
                "reference_links": ["https://wpscan.com/"],
                "evidence": {"usernames": usernames},
            }
        )

    if not vulnerable_plugins and not users:
        findings.append(
            {
                "severity": "informativo",
                "title": "WPScan não encontrou plugins vulneráveis nem usuários enumeráveis",
                "cwe": None,
                "owasp_category": None,
                "description": f"WPScan rodou contra {url} (WordPress {wp_version or 'versão não detectada'}) sem encontrar plugins com vulnerabilidades conhecidas nem usuários enumeráveis.",
                "impact": "Nenhum indício encontrado nesta verificação.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"wp_version": wp_version},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
