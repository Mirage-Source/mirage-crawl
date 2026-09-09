FROM python:3.12-slim

RUN groupadd --system crawl && \
    useradd --system \
    --gid crawl \
    --no-create-home \
    --shell /usr/sbin/nologin \
    crawl

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# /app/data (CRAWL_LOG_DIR/CRAWL_SECRET_FILE) is where the volume mounts --
# create and chown it here, before switching users, so a fresh volume
# inherits ownership the non-root process can actually write to. (Skipping
# this is exactly the bug that dropped real mirage-core sessions on the
# fleet_queue volume -- see mirage-core's DEPLOYMENT.md.)
RUN mkdir -p /app/data && chown -R crawl:crawl /app/data /app/config

USER crawl
EXPOSE 8080
CMD ["python", "run.py"]
