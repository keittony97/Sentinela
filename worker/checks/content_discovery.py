"""Descoberta ATIVA de conteúdo (força bruta de diretórios/arquivos) via ffuf.

Ferramenta "content_discovery": ATIVA — gera tráfego real de força bruta
contra o alvo (centenas de requisições), por isso só disponível em
projetos "Ambiente de Teste" autorizados (Nível 1 — Detecção Ativa), nunca
em "Verificação Externa". Usa uma wordlist pequena e curada embutida (não
uma wordlist gigante de terceiros) para manter o tempo de execução
razoável; ajustar CANDIDATE_WORDS ou apontar pra uma wordlist maior no
disco se precisar de mais cobertura.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

OWASP_EXPOSURE = "A01:2021 - Broken Access Control"

CANDIDATE_WORDS = [
    "admin", "administrator", "login", "wp-admin", "api", "api/v1", "api/v2",
    "backup", "backups", "old", "test", "staging", "dev", "config", "configs",
    "uploads", "upload", "files", "assets", "static", "private", "internal",
    "dashboard", "panel", "cpanel", "phpmyadmin", "adminer", "console",
    "swagger", "swagger-ui", "graphql", "actuator", "health", "status",
    "debug", "server-status", "server-info", "docs", "documentation",
    ".well-known/security.txt", "sitemap.xml", "robots.txt", "crossdomain.xml",
    "temp", "tmp", "cache", "logs", "log", "db", "database", "dump",
    "install", "setup", "wp-login.php", "administrator/index.php",
    "user", "users", "account", "accounts", "profile", "settings",
]

INTERESTING_STATUS = {200, 204, 301, 302, 401, 403}


def _find_ffuf() -> str | None:
    return shutil.which("ffuf")


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    base = url.rstrip("/")
    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o host de {url}")
        return logs, findings

    ffuf_binary = _find_ffuf()
    if not ffuf_binary:
        log("warning", "ffuf não encontrado nesta máquina — descoberta de conteúdo pulada.")
        findings.append(
            {
                "severity": "informativo",
                "title": "Descoberta de conteúdo via ffuf não executada (binário não encontrado)",
                "cwe": None,
                "owasp_category": None,
                "description": "A ferramenta 'content_discovery' precisa do binário 'ffuf' disponível no PATH do worker.",
                "impact": "Nenhum — apenas informativo. Esta verificação simplesmente não rodou.",
                "recommendation": "Instalar o ffuf na máquina/container do worker (https://github.com/ffuf/ffuf) ou trocar por gobuster/dirsearch.",
                "reference_links": ["https://github.com/ffuf/ffuf"],
                "evidence": {"host": hostname},
            }
        )
        return logs, findings

    with tempfile.TemporaryDirectory() as tmp_dir:
        wordlist_path = Path(tmp_dir) / "wordlist.txt"
        wordlist_path.write_text("\n".join(CANDIDATE_WORDS), encoding="utf-8")

        log("info", f"Rodando ffuf ({len(CANDIDATE_WORDS)} palavras) contra {base}/FUZZ")
        try:
            result = subprocess.run(
                [
                    ffuf_binary,
                    "-u", f"{base}/FUZZ",
                    "-w", str(wordlist_path),
                    "-mc", ",".join(str(c) for c in sorted(INTERESTING_STATUS)),
                    "-of", "json",
                    "-o", str(Path(tmp_dir) / "out.json"),
                    "-rate", "20",
                    "-t", "10",
                    "-timeout", "10",
                    "-s",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            log("error", "ffuf excedeu o tempo limite (180s).")
            return logs, findings
        except Exception as exc:  # noqa: BLE001
            log("error", f"Falha ao executar ffuf: {exc}")
            return logs, findings

        out_path = Path(tmp_dir) / "out.json"
        if not out_path.exists():
            log("error", f"ffuf não gerou saída. stderr: {result.stderr[:300]}")
            return logs, findings

        import json

        try:
            data = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            log("error", f"Falha ao interpretar saída JSON do ffuf: {exc}")
            return logs, findings

    hits = data.get("results", [])
    log("info", f"ffuf encontrou {len(hits)} caminho(s) com status interessante")

    sensitive_hits = [
        h for h in hits
        if any(k in h.get("input", {}).get("FUZZ", "") for k in ("admin", "config", "backup", "debug", "swagger", "actuator", "phpmyadmin", "adminer", "console", "dump", ".well-known"))
    ]

    for hit in hits:
        word = hit.get("input", {}).get("FUZZ", "?")
        status = hit.get("status")
        log("info", f"/{word} -> HTTP {status} ({hit.get('length')} bytes)")

    if sensitive_hits:
        findings.append(
            {
                "severity": "medio",
                "title": f"{len(sensitive_hits)} caminho(s) potencialmente sensível(is) encontrado(s) por força bruta",
                "cwe": "CWE-538",
                "owasp_category": OWASP_EXPOSURE,
                "description": "Força bruta de diretórios/arquivos (ffuf) encontrou caminhos que sugerem funcionalidade administrativa/de debug: "
                + ", ".join(sorted({h.get("input", {}).get("FUZZ", "?") for h in sensitive_hits})),
                "impact": "Painéis administrativos, endpoints de debug ou arquivos de configuração acessíveis publicamente ampliam a superfície de ataque — merecem revisão manual de autenticação/autorização.",
                "recommendation": "Restringir acesso a esses caminhos (autenticação, VPN, IP allowlist) ou removê-los se não forem necessários em produção.",
                "reference_links": ["https://github.com/ffuf/ffuf"],
                "evidence": {"hits": [{"path": h.get("input", {}).get("FUZZ"), "status": h.get("status")} for h in sensitive_hits]},
            }
        )

    findings.append(
        {
            "severity": "informativo",
            "title": f"{len(hits)} caminho(s) encontrado(s) via força bruta de conteúdo (ffuf)",
            "cwe": None,
            "owasp_category": None,
            "description": f"Wordlist de {len(CANDIDATE_WORDS)} entradas testada contra {base}.",
            "impact": "Mapeamento de superfície de ataque.",
            "recommendation": "Revisar a lista completa (nas evidências) e confirmar que todo caminho encontrado é intencional.",
            "reference_links": [],
            "evidence": {"hits": [{"path": h.get("input", {}).get("FUZZ"), "status": h.get("status")} for h in hits]},
        }
    )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
