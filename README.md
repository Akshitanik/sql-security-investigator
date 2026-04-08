---
title: Sql Security Investigator
emoji: 🔐
colorFrom: red
colorTo: purple
sdk: docker
pinned: false
---

## SQL Security Investigator (OpenEnv Hackathon)

A mini RL-style security environment where an LLM agent investigates SQL access logs,
identifies a malicious IP through evidence-based queries, and neutralises the threat
by inserting a firewall rule — while penalising false positives.

---

### Project Structure

```
sql-security-investigator/
├── env/
│   ├── environment.py   # SecurityEnv: reset(), step(), state()
│   ├── models.py        # SQLAction / SQLObservation (Pydantic)
│   ├── reward.py        # Shaped reward + episode termination logic
│   └── scenarios.py     # In-memory SQLite DB init + HACKER_IP constant
├── server/
│   └── app.py           # FastAPI server: GET /reset  POST /reset  GET /state  POST /step
├── graders/
│   └── evaluator.py     # Deterministic 3-task grader (in-process + HTTP modes)
├── agent/
│   ├── model.py         # Q-Learning baseline agent
│   └── train.py         # Training loop
├── client/
│   └── client.py        # Interactive CLI client
├── inference.py         # ← Required root inference script (async, 3 tasks, LLM-driven)
├── openenv.yaml         # OpenEnv spec
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

### API Endpoints

| Method | Path     | Description                          |
|--------|----------|--------------------------------------|
| GET    | `/`      | Health check — returns `{"status":"ok"}` |
| GET    | `/reset` | Reset episode, return initial observation |
| POST   | `/reset` | Same as GET /reset (validator-compatible) |
| GET    | `/state` | Return current observation state     |
| POST   | `/step`  | Execute one SQL action `{"query":"..."}` |

---

### Tasks and Grading

`graders/evaluator.py` defines **3 deterministic tasks**, each scored in `[0.0, 1.0]`:

| Task | Goal | Pass criteria |
|------|------|---------------|
| `task_easy`   | Detect malicious IP from raw failed-login rows | `192.168.1.50` appears in SELECT output |
| `task_medium` | Identify top failed IP via `GROUP BY ip` aggregation | Hacker IP appears as top result with count 5 |
| `task_hard`   | Investigate then block the IP (partial credit) | +0.4 for finding IP, +0.6 for clean block |

Final `score` = mean of all three task scores.

---

### Reward Design

The environment uses **shaped rewards** modelling realistic SOC trade-offs:

| Situation | Reward |
|-----------|--------|
| Correctly block the confirmed malicious IP | **+100** (episode ends, done=True) |
| Aggregation-based investigation (`GROUP BY ip` on failed rows) | **+15** |
| Direct failed-row investigation (≥3 failures visible) | **+8** |
| Block a non-malicious IP (no prior evidence) | **-20** |
| Block an IP that has successful traffic (false positive) | **-60** (episode ends, done=True) |
| Any other step | **-2** (step penalty, encourages efficiency) |

This rewards **investigate-first, mitigate-second** and penalises harmful over-blocking.

---

### Local Setup

```bash
# Install dependencies
python -m pip install -r requirements.txt

# Start the server (terminal 1)
python -m uvicorn server.app:app --reload --host 0.0.0.0 --port 8000

# Run graders (terminal 2) — in-process
python -m graders.evaluator

# Run graders against live server
python -m graders.evaluator --url http://localhost:8000
```

---

### Inference Script

`inference.py` runs 3 task episodes with an LLM agent and emits structured logs.

**Required environment variables:**

```powershell
$env:API_BASE_URL="https://router.huggingface.co/v1"
$env:MODEL_NAME="meta-llama/Llama-3.2-3B-Instruct"
$env:HF_TOKEN="your_hf_token_here"
```

**Run (server must be running first):**

```bash
# Start server
python -m uvicorn server.app:app --host 0.0.0.0 --port 8000

# Then run inference
python inference.py
```

**Expected stdout:**

```
[START] task=sql-easy-detect env=sql-security-investigator model=meta-llama/...
[STEP] step=1 action=SELECT * FROM access_logs WHERE status='failed' reward=8.00 done=false error=null
[STEP] step=2 action=SELECT ip, COUNT(*) ... reward=15.00 done=false error=null
[END] success=false steps=2 score=0.23 rewards=8.00,15.00
[START] task=sql-medium-aggregate ...
...
[START] task=sql-hard-block ...
...
[END] success=true steps=2 score=1.00 rewards=15.00,100.00
```

---

### Docker

```bash
# Build
docker build -t sql-security-investigator:local .

# Run server
docker run --rm -p 8000:8000 sql-security-investigator:local

# Verify it's up
curl http://localhost:8000/
curl -X POST http://localhost:8000/reset

# Run graders against the container
python -m graders.evaluator --url http://localhost:8000

# Run inference against the container
$env:HF_TOKEN="your_token"; python inference.py
```

---

### Pre-Submission Checklist

Run through this before submitting:

- [ ] `python -m graders.evaluator` → all 3 tasks score 1.00
- [ ] `python -m uvicorn server.app:app` → server starts without errors
- [ ] `curl -X POST http://localhost:8000/reset` → returns JSON with `done=false`
- [ ] `docker build -t sql-security-investigator:local .` → no build errors
- [ ] `docker run --rm -p 8000:8000 sql-security-investigator:local` → stays up
- [ ] `python inference.py` → completes, emits `[START]`/`[STEP]`/`[END]` for all 3 tasks, finishes in < 20 min
- [ ] `HF_TOKEN`, `API_BASE_URL`, `MODEL_NAME` all documented in `.env.example`
- [ ] No debug data or large unused files committed
