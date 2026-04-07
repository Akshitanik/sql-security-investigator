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

Example:

```powershell
$env:API_BASE_URL="https://your-openai-compatible-endpoint/v1"
$env:MODEL_NAME="gpt-4o-mini"
$env:HF_TOKEN="your_token_here"
python inference.py
```

### Docker

```bash
docker build -t sql-security-investigator:local .
docker run --rm -p 8000:8000 sql-security-investigator:local
```
