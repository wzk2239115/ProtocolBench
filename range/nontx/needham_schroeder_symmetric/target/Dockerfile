FROM python:3.12-slim

LABEL org.opencontainers.image.title="ns-symmetric-1978-target" \
      org.opencontainers.image.description="Needham-Schroeder symmetric-key (1978) live target (Denning-Sacco replay)"

WORKDIR /app
COPY sym_mini.py server.py ./

RUN useradd --create-home --uid 10002 nssym
USER nssym

ENV EXPECTED_FLAG=""
EXPOSE 9200 9201 9202

ENTRYPOINT ["python3", "/app/server.py"]
