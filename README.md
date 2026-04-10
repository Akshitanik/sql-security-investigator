---
title: SQL Security Investigator
emoji: "🔐"
colorFrom: red
colorTo: blue
sdk: docker
pinned: false
---

# SQL Security Investigator

SQL Security Investigator is a small benchmark-style security environment where an
agent inspects SQL access logs, identifies the malicious IP, and blocks it by
inserting a firewall rule.

## Project Structure

```text
sql-security-investigator/
|-- env/
|   |-- environment.py
|   |-- models.py
|   |-- reward.py
|   `-- scenarios.py
|-- server/
|   `-- app.py
|-- graders/
|   `-- evaluator.py
|-- agent/
|   |-- model.py
|   `-- train.py
|-- client/
|   `-- client.py
|-- inference.py
|-- openenv.yaml
|-- Dockerfile
|-- requirements.txt
`-- .env.example
```

## API

- `GET /` health check
- `GET /reset` reset the episode
- `POST /reset` reset the episode
- `GET /state` fetch the latest observation
- `POST /step` run a SQL action like `{"query":"SELECT * FROM access_logs"}`

## Tasks

- `sql-easy-detect`: detect the malicious IP from failed rows
- `sql-medium-aggregate`: identify the top failed IP with aggregation
- `sql-hard-block`: investigate first, then block the malicious IP

## Local Run

```bash
python -m pip install -r requirements.txt
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000
```

In another terminal:

```bash
python -m graders.evaluator
python -m graders.evaluator --url http://localhost:8000
python inference.py
```

## Environment Variables

```bash
API_BASE_URL=https://router.huggingface.co/v1
MODEL_NAME=meta-llama/Llama-3.2-3B-Instruct
HF_TOKEN=your_hf_token
LLM_TIMEOUT_SECONDS=8
BASE_URL=http://127.0.0.1:8000
```

`inference.py` still runs without `HF_TOKEN`; it will fall back to deterministic
queries so the benchmark remains runnable in offline environments.

## Docker

```bash
docker build -t sql-security-investigator:local .
docker run --rm -p 7860:7860 sql-security-investigator:local
```

## Submission Checklist

- `python -m graders.evaluator` returns a score of `1.00`
- `python -m uvicorn server.app:app --host 0.0.0.0 --port 8000` starts cleanly
- `python inference.py` completes all three tasks
- `docker build -t sql-security-investigator:local .` succeeds
