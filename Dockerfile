 FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install dependencies
COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY env/ ./env/
COPY agent/ ./agent/
COPY server/ ./server/
COPY graders/ ./graders/
COPY client/ ./client/
COPY openenv.yaml ./
COPY inference.py ./

# Expose the FastAPI port
EXPOSE 7860

# Start the server
CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
