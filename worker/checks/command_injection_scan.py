"""Injeção de comando de SO ATIVA via Commix.

Ferramenta "command_injection_scan": ATIVA — dispara payloads reais de
injeção de comando de SO contra os parâmetros de query da URL. Só
disponível em projetos "Ambiente de Teste" autorizados (Nível 1 —
Detecção Ativa).
"""

import re
import shutil
import subprocess
from urllib.parse import parse_qs, urlparse

OWASP_INJECTION = "A03:2021 - Injection"

VULNERABLE_PATTERNS = [
    re.compile(r"is\s+vulnerable\b", re.IGNORECASE),
    re.compile(r"injection\s+technique\(s\)\s+found", re.IGNORECASE),
]


def _find_commix() -> list[str] | None:
    binary = shutil.which("commix")
    if binary:
        return [binary]
    script = shutil.which("commix.py")
    if script:
        return [script]
    return None


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    params = parse_qs(urlparse(url).query)
    if not params:
        log("info", f"{url} não tem parâmetros de query — Commix precisa de ao menos um parâmetro pra testar.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Commix não executado — URL sem parâmetros de query",
                "cwe": None,
                "owasp_category": None,
                "description": f"A URL {url} não tem parâmetros (?chave=valor) para o Commix testar.",
                "impact": "Nenhum — esta ferramenta testa parâmetros de URL existentes.",
                "recommendation": "Se o alvo tiver endpoints com parâmetros em outras URLs, rodar apontando para essas URLs específicas.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    commix_cmd = _find_commix()
    if not commix_cmd:
        log("warning", "Commix não encontrado nesta máquina — verificação de injeção de comando pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação via Commix não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'command_injection_scan' precisa do Commix disponível no PATH do worker (binário 'commix' ou 'commix.py').",
                "impact": "Nenhum — apenas informativo. Esta verificação simplesmente não rodou.",
                "recommendation": "Instalar o Commix na máquina/container do worker (https://github.com/commixproject/commix).",
                "reference_links": ["https://github.com/commixproject/commix"],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log("info", f"Rodando Commix contra {url}")
    try:
        result = subprocess.run(
            [*commix_cmd, "--url", url, "--batch", "--quiet"],
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log("error", "Commix excedeu o tempo limite (180s).")
        return logs, findings
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao executar Commix: {exc}")
        return logs, findings

    output = result.stdout
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            log("info", stripped[:300])

    is_vulnerable = any(p.search(output) for p in VULNERABLE_PATTERNS)

    if is_vulnerable:
        log("warning", "Commix confirmou injeção de comando de SO explorável.")
        findings.append(
            {
                "severity": "critico",
                "title": "Injeção de comando de SO confirmada pelo Commix",
                "cwe": "CWE-78",
                "owasp_category": OWASP_INJECTION,
                "description": f"Commix confirmou que {url} é vulnerável a injeção de comando de sistema operacional.",
                "impact": "Um atacante pode executar comandos arbitrários no servidor — comprometimento total do sistema, incluindo leitura/escrita de arquivos e movimento lateral na rede.",
                "recommendation": "Nunca passar entrada do usuário diretamente para chamadas de shell/sistema. Usar APIs seguras (sem invocar shell) e validar/allowlist rigorosamente qualquer entrada que precise chegar a um comando do SO.",
                "reference_links": ["https://owasp.org/www-community/attacks/Command_Injection", "https://github.com/commixproject/commix"],
                "evidence": {"url": url, "output_excerpt": output[-2000:]},
            }
        )
    else:
        log("info", "Commix não confirmou injeção de comando.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Commix não confirmou injeção de comando de SO",
                "cwe": None,
                "owasp_category": None,
                "description": f"Commix testou os parâmetros de {url} sem confirmar injeção de comando.",
                "impact": "Nenhum indício confirmado nesta verificação.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
