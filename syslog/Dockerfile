FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY syslog_receiver.py .
COPY geoip_lookup.py .

EXPOSE 5514/udp
EXPOSE 5514/tcp

CMD ["python", "-u", "syslog_receiver.py"]
