"""Análise profunda de TLS via testssl.sh (handshake padrão).

Ferramenta "tls_scan": passiva — testssl.sh só faz o handshake TLS que
qualquer navegador faria (não envia payload, não faz brute-force), só
que inspeciona a fundo: protocolos suportados, cifras oferecidas e
vulnerabilidades conhecidas (Heartbleed, POODLE, BREACH, LUCKY13, etc).
Disponível em qualquer modalidade legal, em ambas ("Verificação Externa"
e "Ambiente de Teste") — decisão registrada em CLAUDE.md.

Complementa (não substitui) o `security_headers.py`, que já faz uma
checagem rápida e leve de expiração de certificado via `ssl` do Python,
sem depender de nenhum binário externo.
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
from urllib.parse import urlparse

import net  # noqa: F401 — não usado diretamente aqui (testssl.sh não passa pelo httpx),
# mas mantém o padrão de módulos que tocam rede confiando na store de certificados do SO.

# Localiza o binário/script na seguinte ordem: PATH (ex: apt install no
# Docker), depois o clone vendorizado em worker/vendor/testssl.sh (dev
# local nesta máquina, ou COPY no Dockerfile).
_VENDORED_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "vendor", "testssl.sh", "testssl.sh")
)

# testssl.sh usa uma escala de severidade própria (OK/INFO/WARN/LOW/
# MEDIUM/HIGH/CRITICAL). Na prática, WARN quase sempre indica limitação
# do próprio scanner (ex: "RC4 ciphers not supported by local OpenSSL",
# "couldn't be tested, socket problem") e não um problema real do alvo —
# confirmado testando contra um alvo real. Só LOW pra cima vira finding.
SEVERITY_MAP = {
    "LOW": "baixo",
    "MEDIUM": "medio",
    "HIGH": "alto",
    "CRITICAL": "critico",
}

OWASP_CRYPTO = "A02:2021 - Cryptographic Failures"


def _find_testssl() -> list[str] | None:
    found = shutil.which("testssl.sh") or shutil.which("testssl")
    if found:
        return [found]
    if os.path.exists(_VENDORED_PATH):
        return ["bash", _VENDORED_PATH]
    return None


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        log("error", f"Não foi possível extrair o host de {url}")
        return logs, findings
    if parsed.scheme != "https":
        log("info", f"{url} não é HTTPS — nada para o testssl.sh analisar.")
        return logs, findings

    testssl_cmd = _find_testssl()
    if not testssl_cmd:
        log("warning", "testssl.sh não encontrado nesta máquina — análise profunda de TLS pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Análise profunda de TLS via testssl.sh não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'tls_scan' precisa do testssl.sh disponível no PATH do worker ou clonado em worker/vendor/testssl.sh.",
                "impact": "Nenhum — apenas informativo. Esta verificação simplesmente não rodou.",
                "recommendation": "Instalar/clonar o testssl.sh (https://testssl.sh) na máquina/container do worker.",
                "reference_links": ["https://testssl.sh/"],
                "evidence": {"host": hostname},
            }
        )
        return logs, findings

    # Resolve o IP via Python em vez de deixar o testssl.sh resolver
    # sozinho — o mecanismo de DNS dele depende de `dig`/`host`, que não
    # existem por padrão neste ambiente (Git Bash/Windows), e falha
    # mesmo quando o alvo resolve normalmente por qualquer outra via.
    try:
        ip = socket.gethostbyname(hostname)
    except Exception as exc:  # noqa: BLE001
        log("error", f"Falha ao resolver DNS de {hostname}: {exc}")
        return logs, findings

    log("info", f"Rodando testssl.sh (handshake TLS padrão) contra {hostname} ({ip})")
    log("info", "testssl.sh abre muitas conexões TLS separadas — pode levar de 1 a vários minutos, dependendo da latência de rede até o alvo.")

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "testssl-out.json")
        try:
            result = subprocess.run(
                [
                    *testssl_cmd,
                    "--fast",
                    "-p",
                    "-U",
                    "--ip",
                    ip,
                    "--jsonfile",
                    out_path,
                    hostname,
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )
        except subprocess.TimeoutExpired:
            log("error", "testssl.sh excedeu o tempo limite (600s).")
            return logs, findings
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao executar testssl.sh: {exc}")
            return logs, findings

        # testssl.sh retorna código de saída não-zero quando encontra
        # problemas (comportamento esperado, não é falha de execução) —
        # por isso não checamos returncode, só se o arquivo de saída existe.
        if not os.path.exists(out_path):
            log("error", f"testssl.sh não gerou saída. stderr: {result.stderr[:300]}")
            return logs, findings

        try:
            with open(out_path, encoding="utf-8") as f:
                entries = json.load(f)
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao interpretar saída JSON do testssl.sh: {exc}")
            return logs, findings

    log("info", f"testssl.sh retornou {len(entries)} verificação(ões)")

    for entry in entries:
        severity_raw = entry.get("severity", "")
        mapped = SEVERITY_MAP.get(severity_raw)
        if not mapped:
            continue

        check_id = entry.get("id", "desconhecido")
        finding_text = entry.get("finding", "")
        cwe = entry.get("cwe")
        cve = entry.get("cve")

        log("warning", f"{check_id}: {finding_text} [{severity_raw}]")
        findings.append(
            {
                "severity": mapped,
                "title": f"TLS: {check_id} — {finding_text}",
                "cwe": cwe,
                "owasp_category": OWASP_CRYPTO,
                "description": f"testssl.sh reportou '{check_id}' com severidade {severity_raw} em {hostname}: {finding_text}",
                "impact": "Configuração de TLS abaixo do recomendado pode permitir ataques de downgrade, interceptação de tráfego ou quebra da criptografia, dependendo do item específico.",
                "recommendation": "Revisar a configuração de TLS do servidor (protocolos, cifras, compressão HTTP) conforme recomendações atuais — ex: Mozilla SSL Configuration Generator.",
                "reference_links": (
                    ["https://testssl.sh/", "https://wiki.mozilla.org/Security/Server_Side_TLS"]
                    + ([f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve else [])
                ),
                "evidence": {"id": check_id, "severity": severity_raw, "finding": finding_text, "cve": cve, "host": hostname, "ip": ip},
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum problema de TLS encontrado pelo testssl.sh",
                "cwe": None,
                "owasp_category": None,
                "description": f"testssl.sh analisou {hostname} ({len(entries)} verificações) e não encontrou nenhum item classificado como LOW ou pior.",
                "impact": "Nenhum.",
                "recommendation": "Nenhuma ação necessária com base nesta verificação.",
                "reference_links": ["https://testssl.sh/"],
                "evidence": {"host": hostname, "ip": ip, "checks_run": len(entries)},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
