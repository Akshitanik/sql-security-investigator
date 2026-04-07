## SQL Security Investigator (OpenEnv Hackathon)

This project is a mini RL-style security environment where an agent investigates SQL access logs, identifies a malicious IP, and blocks it via SQL actions.

### Project Structure

- `env/`: core environment (`reset`, `step`, `state`), reward logic, schemas, scenarios
- `server/`: FastAPI service exposing environment endpoints
- `graders/`: deterministic 3-task evaluator
- `agent/`: baseline Q-learning prototype
- `openenv.yaml`: OpenEnv metadata and scoring config
- `inference.py`: root inference script using OpenAI-compatible client + required env vars

### API Endpoints

- `GET /` health message
- `GET /reset` resets episode and returns initial observation
- `GET /state` returns current observation state
- `POST /step` executes one SQL action

### Tasks and Grading

`graders/evaluator.py` defines 3 tasks (easy/medium/hard), each scored in `[0.0, 1.0]`:

- easy: detect malicious IP in failed log rows
- medium: detect malicious IP through aggregation query
- hard: block malicious IP and complete episode

Final `score` is the mean of task scores.

### Reward Design (Real-World Utility)

The environment now uses shaped rewards to model realistic SOC trade-offs:

- `+15` for strong aggregation-based investigation (`GROUP BY ip` over failed logs)
- `+8` for useful failed-login investigation queries
- `+100` for correctly blocking the confirmed malicious IP
- `-20` for blocking non-malicious IPs without evidence
- `-60` and episode termination for false positives that block IPs seen with successful traffic
- small per-step penalty to encourage efficient incident response

This encourages agents to investigate first, mitigate second, and avoid harmful over-blocking.

### Local Setup

```bash
python -m pip install -r requirements.txt
python -m uvicorn server.app:app --reload --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
python -m graders.evaluator
```

### Inference Script Requirements

`inference.py` expects:

- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`
- `LOCAL_IMAGE_NAME` (optional; only needed if using docker-image-based env loading)

Example:

```powershell
$env:API_BASE_URL="https://your-openai-compatible-endpoint/v1"
$env:MODEL_NAME="gpt-4o-mini"
$env:HF_TOKEN="your_token_here"
python inference.py
```

Structured stdout emitted by `inference.py`:

- `[START] task=<task_name> env=<benchmark> model=<model_name>`
- `[STEP] step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>`
- `[END] success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>`

### Docker

```bash
docker build -t sql-security-investigator:local .
docker run --rm -p 8000:8000 sql-security-investigator:local
```
