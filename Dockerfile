FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl \
    && useradd --system --uid 10001 --user-group --create-home --home-dir /home/app app

USER 10001:10001
WORKDIR /home/app
# Only used when OPNSENSE_MCP_TRANSPORT=streamable-http; stdio ignores it.
EXPOSE 8000

ENTRYPOINT ["opnsense-mcp"]
