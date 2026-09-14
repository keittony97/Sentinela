"""Verificação passiva de storage público mal configurado (S3/GCS).

Ferramenta "storage_exposure": testa nomes de bucket comuns derivados do
domínio do alvo contra os endpoints públicos de listagem do S3 e do GCS.
Só faz GET normal (o mesmo que abrir a URL no navegador) — não tenta
autenticar, não escreve nada. Baixa cobertura por natureza (depende de
adivinhar o nome certo), mas é a técnica passiva padrão usada em bug
bounty pra esse tipo de achado.
"""

from urllib.parse import urlparse

import httpx

import net  # noqa: F401 — aplica o patch de TLS (ver net.py)


def _candidate_names(hostname: str) -> list[str]:
    labels = hostname.lower().split(".")
    base = labels[-2] if len(labels) >= 2 else labels[0]
    return [
        base,
        f"{base}-assets",
        f"{base}-backup",
        f"{base}-backups",
        f"{base}-files",
        f"{base}-static",
        f"{base}-uploads",
        f"{base}-data",
        f"{base}-prod",
    ]


def run(url: str) -> tuple[list[dict], list[dict]]:
    logs: list[dict] = []
    findings: list[dict] = []

    def log(level: str, message: str) -> None:
        logs.append({"level": level, "message": message})

    hostname = urlparse(url).hostname
    if not hostname:
        log("error", f"Não foi possível extrair o domínio de {url}")
        return logs, findings

    candidates = _candidate_names(hostname)
    log("info", f"Testando {len(candidates)} nome(s) de bucket comuns derivados de '{hostname}' em S3 e GCS")

    for name in candidates:
        for provider, bucket_url in (
            ("S3", f"https://{name}.s3.amazonaws.com/"),
            ("GCS", f"https://storage.googleapis.com/{name}/"),
        ):
            try:
                resp = httpx.get(bucket_url, timeout=10)
            except Exception as exc:  # noqa: BLE001
                log("error", f"{bucket_url}: falha na requisição ({exc})")
                continue

            if resp.status_code == 200 and "ListBucketResult" in resp.text:
                log("warning", f"Bucket {provider} público e listável: {bucket_url} (ownership não confirmado)")
                findings.append(
                    {
                        # "medio", não "alto": nomes de bucket são um namespace GLOBAL
                        # (S3/GCS) — o nome bater com o domínio do alvo não prova que o
                        # bucket pertence a essa organização. Pode ser de terceiros sem
                        # nenhuma relação. Por isso a severidade fica moderada até
                        # alguém confirmar manualmente a propriedade.
                        "severity": "medio",
                        "title": f"Possível bucket {provider} público e listável: {name} (confirmar propriedade)",
                        "cwe": "CWE-284",
                        "owasp_category": "A01:2021 - Broken Access Control",
                        "description": (
                            f"{bucket_url} responde HTTP 200 com uma listagem pública de objetos. "
                            f"O nome '{name}' foi derivado do domínio do alvo, mas nomes de bucket "
                            "em S3/GCS são um namespace global — isso NÃO confirma que o bucket "
                            "pertence à organização dona do alvo. Confira o conteúdo listado "
                            "(nomes de arquivo, metadados) antes de tratar como achado real."
                        ),
                        "impact": "Se o bucket realmente pertencer à organização: qualquer pessoa pode listar (e possivelmente baixar) todos os arquivos, incluindo dados sensíveis, backups ou credenciais.",
                        "recommendation": f"Primeiro confirmar se o bucket '{name}' realmente pertence à organização (conferir conteúdo/metadados). Se pertencer, revisar as permissões e desabilitar listagem/leitura pública, a menos que seja intencional (ex: assets de site público).",
                        "reference_links": [
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
                        ],
                        "evidence": {
                            "bucket_url": bucket_url,
                            "provider": provider,
                            "listing_sample": resp.text[:1000],
                        },
                    }
                )
            elif resp.status_code == 403:
                log("info", f"{bucket_url}: bucket existe mas listagem negada (403) — configuração correta")
            elif resp.status_code == 404:
                log("info", f"{bucket_url}: não existe (404)")
            else:
                log("info", f"{bucket_url}: HTTP {resp.status_code}")

    if not findings:
        findings.append(
            {
                "severity": "informativo",
                "title": "Nenhum bucket público óbvio encontrado nos nomes testados",
                "cwe": None,
                "owasp_category": None,
                "description": f"Nenhum dos {len(candidates)} nomes de bucket testados (derivados de '{hostname}') estava publicamente listável em S3/GCS.",
                "impact": "Nenhum. Cobertura limitada — só cobre nomes previsíveis, não é uma garantia de que não existe bucket exposto com outro nome.",
                "recommendation": "Nenhuma ação necessária com base nesta verificação.",
                "reference_links": [],
                "evidence": {"tested_names": candidates},
            }
        )

    log("info", f"Verificação concluída: {len(findings)} achado(s).")
    return logs, findings
