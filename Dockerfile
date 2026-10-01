FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never

# Dependencies first, so code changes don't reinstall them.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH" HOST=0.0.0.0
RUN useradd --create-home app
USER app

# One image, two services. PACT_ROLE=admin runs the Admin API on its own; otherwise the board,
# which runs the (idempotent) migrations on start so deploys stay one step.
CMD ["sh", "-c", "if [ \"$PACT_ROLE\" = admin ]; then exec pact-admin-api; else pact-admin migrate && exec pact-board; fi"]
