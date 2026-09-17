FROM python:3.12-slim

LABEL org.opencontainers.image.title="nspk-1978-target" \
      org.opencontainers.image.description="Needham-Schroeder public-key (1978) live target (Lowe MITM)"

WORKDIR /app
COPY rsa_mini.py server.py ./

RUN useradd --create-home --uid 10001 nspk
USER nspk

ENV EXPECTED_FLAG=""
EXPOSE 9100 9101 9102

ENTRYPOINT ["python3", "/app/server.py"]
