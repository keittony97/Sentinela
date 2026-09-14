FROM python:3.12-slim

WORKDIR /app

# nmap: usado pela ferramenta "port_scan" (checks/port_scan.py) para
# reconhecimento de portas/serviços — substitui a dependência de um
# serviço de terceiros (Shodan/Censys).
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
