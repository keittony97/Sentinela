FROM python:3.12-slim

WORKDIR /app

# nmap: usado pela ferramenta "port_scan" (checks/port_scan.py) para
# reconhecimento de portas/serviços — substitui a dependência de um
# serviço de terceiros (Shodan/Censys). git: só pra clonar o testssl.sh
# na sequência. bsdextrautils: traz o `hexdump` que o testssl.sh precisa
# (no Debian usado pela imagem python:3.12-slim, hexdump vem desse
# pacote, não do coreutils).
RUN apt-get update && apt-get install -y --no-install-recommends nmap git bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh: usado pela ferramenta "tls_scan" (checks/tls_scan.py) para
# análise profunda de TLS (protocolos, cifras, vulnerabilidades
# conhecidas). Não tem pacote apt oficial — clonar é o caminho padrão.
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /app/vendor/testssl.sh

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
