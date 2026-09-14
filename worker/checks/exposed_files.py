"""Verificação passiva de arquivos/configs sensíveis publicamente acessíveis.

Ferramenta "exposed_files": só faz requisições GET normais em caminhos
bem conhecidos (equivalente a digitar a URL no navegador) — não explora
nada, não faz brute-force de senha, não envia payload. Disponível em
qualquer modalidade legal.
"""

import uuid
from urllib.parse import urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)

# (caminho, trechos que devem aparecer no corpo pra confirmar que é o
# arquivo de verdade e não uma página de erro genérica retornando 200,
# severidade)
CANDIDATE_PATHS: list[tuple[str, list[str] | None, str]] = [
    ("/.env", ["="], "alto"),
    ("/.git/config", ["[core]", "repositoryformatversion"], "alto"),
    ("/.git/HEAD", ["ref:"], "alto"),
    ("/.aws/credentials", ["aws_access_key_id"], "critico"),
    ("/.htpasswd", [":"], "alto"),
    ("/config.php.bak", None, "alto"),
    ("/wp-config.php.bak", None, "alto"),
    ("/docker-compose.yml", ["services:"], "medio"),
    ("/.DS_Store", None, "baixo"),
    ("/backup.zip", None, "medio"),
    ("/backup.sql", None, "critico"),
    ("/composer.json", ["\"require\""], "informativo"),
    ("/package.json", ["\"dependencies\""], "informativo"),
]

OWASP_EXPOSURE = "A01:2021 - Broken Access Control"


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    # Achados de "arquivo exposto" são sobre a raiz do site, não sobre um
    # endpoint/página específica — descarta path, query string e fragment
    # da URL do alvo. Sem isso, uma URL com "?a=1&b=2" faz "/backup.sql"
    # virar parte da query string em vez de um path novo, e servidores que
    # ecoam a query (ex: endpoints tipo /get) respondem 200 pra qualquer
    # coisa, gerando falso positivo.
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    log("info", f"Checando {len(CANDIDATE_PATHS)} caminhos comuns de arquivos sensíveis em {base}")

    # Servidores mal configurados às vezes retornam HTTP 200 pra qualquer
    # caminho (SPA fallback, página de erro customizada). Sondar um
    # caminho aleatório primeiro pra ter uma "impressão digital" desse
    # comportamento e não confundir isso com um arquivo de verdade.
    probe_path = f"/__sentinela_probe_{uuid.uuid4().hex[:12]}"
    baseline_status: int | None = None
    baseline_len: int | None = None
    try:
        baseline = httpx.get(base + probe_path, timeout=10, follow_redirects=True)
        baseline_status = baseline.status_code
        baseline_len = len(baseline.content)
        log("info", f"Baseline (caminho inexistente): HTTP {baseline_status}, {baseline_len} bytes")
    except Exception as exc:  # noqa: BLE001
        log("warning", f"Falha ao obter baseline: {exc}")

    for path, signature_hints, severity in CANDIDATE_PATHS:
        try:
            resp = httpx.get(base + path, timeout=10, follow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            log("error", f"{path}: falha na requisição ({exc})")
            continue

        if resp.status_code != 200:
            log("info", f"{path}: HTTP {resp.status_code}")
            continue

        if baseline_status == 200 and len(resp.content) == baseline_len:
            log("info", f"{path}: HTTP 200, mas parece ser a mesma página padrão do servidor (soft 404), ignorado")
            continue

        body_sample = resp.text[:4000] if resp.text else ""
        matched = True if not signature_hints else any(hint in body_sample for hint in signature_hints)

        if not matched:
            log("info", f"{path}: HTTP 200 mas conteúdo não confere com o esperado, ignorado (provável falso positivo)")
            continue

        log("warning", f"{path}: acessível publicamente (HTTP 200) — possível exposição")
        findings.append(
            {
                "severity": severity,
                "title": f"Arquivo potencialmente sensível acessível publicamente: {path}",
                "cwe": "CWE-538",
                "owasp_category": OWASP_EXPOSURE,
                "description": f"Uma requisição GET normal em {base}{path} retornou HTTP 200 com conteúdo compatível com esse tipo de arquivo.",
                "impact": "Dependendo do arquivo, pode expor credenciais, chaves de API, histórico de código-fonte (via .git) ou detalhes de infraestrutura.",
                "recommendation": f"Remover ou bloquear o acesso público a {path} (regra no servidor web/proxy) e, se o arquivo continha segredos reais, rotacioná-los imediatamente.",
                "reference_links": ["https://owasp.org/www-project-web-security-testing-guide/"],
                "evidence": {
                    "url": base + path,
                    "status_code": resp.status_code,
                    "body_sample": body_sample[:500],
                },
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
