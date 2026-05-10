FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install runtime deps first so the deps layer is cached.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App source
COPY app ./app
COPY launch.py ./launch.py
COPY sources.yaml watchlist.yaml suppression.yaml ./

# Non-root user; data volume mounts to /app/data
RUN useradd --create-home --uid 10001 threatintel \
 && mkdir -p /app/data \
 && chown -R threatintel:threatintel /app
USER threatintel

EXPOSE 8501

# Default to launching the dashboard. Override via `command:` in compose.
CMD ["python", "-m", "streamlit", "run", "app/ui/streamlit_app.py", \
     "--server.port=8501", "--server.address=0.0.0.0", "--server.headless=true"]
