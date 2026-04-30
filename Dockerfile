FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

ENV PYTHONUNBUFFERED=1

RUN useradd -m ber211 && chown -R ber211:ber211 /app
USER ber211

ENTRYPOINT ["python", "main.py"]
