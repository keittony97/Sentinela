"""SQL Injection ATIVA via sqlmap.

Ferramenta "sqlmap_scan": ATIVA — dispara payloads reais de teste de SQLi
(baseado em erro, boolean-blind, time-blind, UNION) via sqlmap contra os
parâmetros de query já existentes na URL. Muito mais abrangente que
'basic_injection_probe' (que só testa uma aspas simples). Só disponível
em projetos "Ambiente de Teste" autorizados (Nível 1 — Detecção Ativa).
"""

import re
import shutil
import subprocess
import tempfile
from urllib.parse import parse_qs, urlparse

OWASP_INJECTION = "A03:2021 - Injection"

VULNERABLE_PATTERN = re.compile(r"Parameter:\s*([^\s(]+)\s*\(([^)]+)\)", re.IGNORECASE)
TYPE_LINE_PATTERN = re.compile(r"Type:\s*(.+)", re.IGNORECASE)
TITLE_LINE_PATTERN = re.compile(r"Title:\s*(.+)", re.IGNORECASE)


def _find_sqlmap() -> list[str] | None:
    binary = shutil.which("sqlmap")
    if binary:
        return [binary]
    # sqlmap também é comumente instalado como script Python sem entry
    # point no PATH (ex: clone do repositório oficial).
    script = shutil.which("sqlmap.py")
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
        log("info", f"{url} não tem parâmetros de query — sqlmap precisa de ao menos um parâmetro pra testar.")
        findings.append(
            {
                "severity": "informativo",
                "title": "sqlmap não executado — URL sem parâmetros de query",
                "cwe": None,
                "owasp_category": None,
                "description": f"A URL {url} não tem parâmetros (?chave=valor) para o sqlmap testar.",
                "impact": "Nenhum — esta ferramenta testa parâmetros de URL existentes.",
                "recommendation": "Se o alvo tiver endpoints com parâmetros em outras URLs, rodar apontando para essas URLs específicas.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    sqlmap_cmd = _find_sqlmap()
    if not sqlmap_cmd:
        log("warning", "sqlmap não encontrado nesta máquina — verificação de SQLi avançada pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Verificação via sqlmap não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'sqlmap_scan' precisa do sqlmap disponível no PATH do worker (binário 'sqlmap' ou 'sqlmap.py').",
                "impact": "Nenhum — apenas informativo. 'basic_injection_probe' já cobre uma checagem leve de SQLi baseado em erro.",
                "recommendation": "Instalar o sqlmap na máquina/container do worker (https://github.com/sqlmapproject/sqlmap).",
                "reference_links": ["https://github.com/sqlmapproject/sqlmap"],
                "evidence": {"url": url},
            }
        )
        return logs, findings

    log("info", f"Rodando sqlmap (nível 1, risco 1, --batch) contra {url}")
    with tempfile.TemporaryDirectory() as tmp_dir:
        try:
            result = subprocess.run(
                [
                    *sqlmap_cmd,
                    "-u", url,
                    "--batch",
                    "--level=1",
                    "--risk=1",
                    "--output-dir", tmp_dir,
                    "--disable-coloring",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            log("error", "sqlmap excedeu o tempo limite (300s).")
            return logs, findings
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao executar sqlmap: {exc}")
            return logs, findings

    output = result.stdout
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("[INFO]", "[*]")):
            log("info", stripped)
        elif stripped.startswith("[WARNING]"):
            log("warning", stripped)
        elif stripped.startswith("[CRITICAL]") or stripped.startswith("[ERROR]"):
            log("error", stripped)

    if "all tested parameters do not appear to be injectable" in output.lower():
        log("info", "sqlmap não encontrou parâmetros injetáveis com nível/risco 1.")
        findings.append(
            {
                "severity": "informativo",
                "title": "sqlmap não encontrou SQL Injection (nível 1, risco 1)",
                "cwe": None,
                "owasp_category": None,
                "description": f"sqlmap testou os parâmetros de {url} em nível 1/risco 1 sem encontrar indícios de SQLi.",
                "impact": "Nenhum indício encontrado neste nível de teste — níveis/riscos mais altos testam mais payloads, mas geram mais tráfego e podem ser mais destrutivos.",
                "recommendation": "Nenhuma ação necessária para esta verificação.",
                "reference_links": [],
                "evidence": {"url": url},
            }
        )
        log("info", f"Verificação concluída: {len(findings)} achado(s).")
        return logs, findings

    # Parsing best-effort da seção "Parameter: X (Y)" que o sqlmap imprime
    # por parâmetro vulnerável, com blocos "Type:"/"Title:" logo abaixo.
    vulnerable_params = []
    lines = output.splitlines()
    for idx, line in enumerate(lines):
        match = VULNERABLE_PATTERN.search(line)
        if not match:
            continue
        param_name, param_location = match.group(1), match.group(2)
        types_found = []
        for follow_up in lines[idx + 1 : idx + 12]:
            type_match = TYPE_LINE_PATTERN.search(follow_up)
            title_match = TITLE_LINE_PATTERN.search(follow_up)
            if type_match:
                types_found.append(type_match.group(1).strip())
            if title_match:
                types_found.append(f"({title_match.group(1).strip()})")
        vulnerable_params.append({"parameter": param_name, "location": param_location, "details": types_found})

    if vulnerable_params:
        for vp in vulnerable_params:
            log("warning", f"sqlmap confirmou SQLi no parâmetro '{vp['parameter']}': {' '.join(vp['details'])}")
            findings.append(
                {
                    "severity": "critico",
                    "title": f"SQL Injection confirmado pelo sqlmap no parâmetro '{vp['parameter']}'",
                    "cwe": "CWE-89",
                    "owasp_category": OWASP_INJECTION,
                    "description": f"sqlmap confirmou injeção SQL no parâmetro '{vp['parameter']}' de {url}. Detalhes: {' '.join(vp['details'])}",
                    "impact": "Um atacante pode ler, alterar ou apagar dados do banco, ou contornar autenticação, dependendo dos privilégios do usuário de banco usado pela aplicação.",
                    "recommendation": f"Usar consultas parametrizadas (prepared statements) para o parâmetro '{vp['parameter']}' em vez de concatenar a entrada diretamente na query SQL.",
                    "reference_links": ["https://owasp.org/www-community/attacks/SQL_Injection", "https://github.com/sqlmapproject/sqlmap"],
                    "evidence": {"url": url, "parameter": vp["parameter"], "location": vp["location"], "details": vp["details"]},
                }
            )
    else:
        log("info", "sqlmap terminou sem confirmar SQLi (saída não reconhecida pelo parser — revisar log bruto).")
        findings.append(
            {
                "severity": "informativo",
                "title": "sqlmap executado — revisar log de execução para detalhes",
                "cwe": None,
                "owasp_category": None,
                "description": f"sqlmap rodou contra {url}, mas o parser desta ferramenta não reconheceu um padrão claro de vulnerabilidade confirmada na saída.",
                "impact": "Indeterminado — recomenda-se revisar o log bruto de execução.",
                "recommendation": "Consultar a tela de log de execução deste scan para o output completo do sqlmap.",
                "reference_links": ["https://github.com/sqlmapproject/sqlmap"],
                "evidence": {"url": url},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
