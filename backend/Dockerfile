# Python 3.13, NOT 3.14: yara-python 4.5.4 publishes no cp314 wheel, so 3.14
# would force a libyara source build.
FROM python:3.13-slim

# libmagic1 backs python-magic's file-type detection.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Samples are never executed — this process only reads them.
RUN mkdir -p /app/storage/samples

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
