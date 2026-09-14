import os

import httpx
import truststore

# Em redes corporativas com proxy TLS próprio (certificado autoassinado na
# cadeia), o bundle da certifi não confia na CA da empresa. truststore usa a
# store de certificados do SO (igual o --use-system-ca do Node no app/),
# em vez de desabilitar a verificação TLS.
truststore.inject_into_ssl()

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SERVICE_ROLE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]

_HEADERS = {
    "apikey": SERVICE_ROLE_KEY,
    "Authorization": f"Bearer {SERVICE_ROLE_KEY}",
    "Content-Type": "application/json",
}


def _client() -> httpx.Client:
    return httpx.Client(base_url=f"{SUPABASE_URL}/rest/v1", headers=_HEADERS, timeout=20)


def select(table: str, params: dict) -> list[dict]:
    with _client() as client:
        resp = client.get(f"/{table}", params=params)
        resp.raise_for_status()
        return resp.json()


def insert(table: str, rows: dict | list[dict]) -> list[dict]:
    with _client() as client:
        resp = client.post(f"/{table}", json=rows, headers={"Prefer": "return=representation"})
        resp.raise_for_status()
        return resp.json()


def update(table: str, params: dict, patch: dict) -> list[dict]:
    with _client() as client:
        resp = client.patch(
            f"/{table}", params=params, json=patch, headers={"Prefer": "return=representation"}
        )
        resp.raise_for_status()
        return resp.json()
