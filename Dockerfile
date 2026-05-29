FROM python:3.12-alpine

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir .

ENTRYPOINT ["api-scanner"]
CMD ["scan", "/project"]
