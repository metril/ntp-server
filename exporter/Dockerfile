FROM alpine:3.20

RUN apk add --no-cache python3 py3-pip

COPY requirements.txt /app/requirements.txt
RUN pip install --break-system-packages --no-cache-dir -r /app/requirements.txt

COPY exporter.py /app/exporter.py

CMD ["python3", "/app/exporter.py"]
