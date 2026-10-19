# Build explicitly from the repository root. Runtime uses an operator-approved
# immutable repo@sha256 digest; the importer never builds or pulls this image.
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HDF5_PLUGIN_PATH=/nonexistent
WORKDIR /app
COPY requirements-native.txt /app/requirements-native.txt
RUN pip install --no-cache-dir -r /app/requirements-native.txt
COPY core/native_import.py core/native_worker.py /app/core/
USER 65532:65532
ENTRYPOINT ["python", "-I", "/app/core/native_worker.py"]
