# One image for all three roles (api, gateway simulator, verify);
# the role is selected by the container command. Pure standard library,
# so the image needs no third-party packages.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/srv

WORKDIR /srv

COPY app ./app
COPY receiver ./receiver
COPY tests ./tests
COPY scripts ./scripts

RUN python -m compileall -q app receiver tests scripts \
    && mkdir -p /data

# API HTTP port inside the container (host publishing is set in compose).
EXPOSE 8080 9090

CMD ["python", "-m", "app.main"]
