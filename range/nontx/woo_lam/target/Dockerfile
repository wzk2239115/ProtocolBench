FROM python:3.12-slim

LABEL org.opencontainers.image.title="woo-lam-target" \
      org.opencontainers.image.description="Woo-Lam (1992/1994) authentication protocol live target (interleaving impersonation)"

WORKDIR /app
COPY sym_mini.py server.py ./

RUN useradd --create-home --uid 10001 woolam
USER woolam

ENV EXPECTED_FLAG=""
EXPOSE 9200 9201 9202

ENTRYPOINT ["python3", "/app/server.py"]