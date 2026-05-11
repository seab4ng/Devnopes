FROM python:3.11-alpine

# Install the kubernetes Python client only — no other runtime deps needed
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

WORKDIR /app
COPY diagnose.py .

ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-u", "diagnose.py"]
