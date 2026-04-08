FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir --force-reinstall Flask==3.1.3

# Copy application code
COPY app.py .
COPY train.py .

# Models directory (will be mounted as volume or copied)
RUN mkdir -p /app/models /app/data

EXPOSE 5000

ENV ML_PORT=5000

CMD ["python", "app.py"]
