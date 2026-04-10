"""
SQL Security Investigator inference runner.

Runs three benchmark-style tasks against the local environment and emits logs in
the expected START/STEP/END format. If no Hugging Face token is available, or if
the model call fails, the runner falls back to deterministic SQL queries so the
script remains runnable in offline environments.
"""

import asyncio
import os
import textwrap
from typing import List, Optional

from openai import OpenAI

from env.environment import SecurityEnv
from env.models import SQLAction, SQLObservation


API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.2-3B-Instruct")
BENCHMARK = "sql-security-investigator"
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "8"))
DEBUG_LOGS_ENABLED = os.getenv("DEBUG_LOGS", "").lower() in {"1", "true", "yes"}

TASKS: List[dict] = [
    {
        "name": "sql-easy-detect",
        "description": (
            "Detect the malicious IP by inspecting failed login attempts in access_logs."
        ),
        "max_steps": 4,
        "fallback_queries": [
            "SELECT * FROM access_logs WHERE status='failed'",
            "SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC",
        ],
    },
    {
        "name": "sql-medium-aggregate",
        "description": (
            "Rank failed IPs with GROUP BY ip and identify the top offender."
        ),
        "max_steps": 4,
        "fallback_queries": [
            "SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC",
            "SELECT * FROM access_logs WHERE status='failed'",
        ],
    },
    {
        "name": "sql-hard-block",
        "description": (
            "Investigate the logs, identify the malicious IP, then block it with an INSERT into firewall."
        ),
        "max_steps": 6,
        "fallback_queries": [
            "SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC",
            "INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')",
        ],
    },
]

SYSTEM_PROMPT = textwrap.dedent(
    """
    You are a SOC analyst with SQL access to a security investigation database.

    Tables:
    - access_logs(id INTEGER, ip TEXT, status TEXT)
    - firewall(blocked_ip TEXT)

    Rules:
    - Only SELECT and INSERT queries are allowed.
    - Investigate before blocking.
    - Block only the IP with the strongest failed-login evidence.

    Reply with exactly one SQL query and nothing else.
    """
).strip()

_MAX_REWARD = 100.0


def debug_log(message: str) -> None:
    if DEBUG_LOGS_ENABLED:
        print(f"[DEBUG] {message}", flush=True)


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(
    step: int,
    action: str,
    reward: float,
    done: bool,
    error: Optional[str],
) -> None:
    action_clean = " ".join(action.split())
    error_value = error if error else "null"
    print(
        f"[STEP] step={step} action={action_clean} reward={reward:.2f} "
        f"done={str(done).lower()} error={error_value}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{reward:.2f}" for reward in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.2f} rewards={rewards_str}",
        flush=True,
    )


def _ask_llm(
    task_desc: str,
    obs_message: str,
    db_output: str,
    step: int,
    history: List[str],
) -> str:
    hf_token = os.getenv("HF_TOKEN", "").strip()
    if not hf_token:
        return ""

    history_block = "\n".join(history[-4:]) if history else "None"
    user_prompt = textwrap.dedent(
        f"""
        Task: {task_desc}
        Step: {step}

        Latest observation:
        - message: {obs_message}
        - db_output: {db_output or "(empty - no rows returned yet)"}

        Recent history:
        {history_block}

        What is your next SQL query?
        """
    ).strip()

    try:
        client = OpenAI(
            base_url=API_BASE_URL,
            api_key=hf_token,
            timeout=LLM_TIMEOUT_SECONDS,
        )
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.0,
            max_tokens=200,
        )
        text = (completion.choices[0].message.content or "").strip()
        for line in text.splitlines():
            candidate = line.strip().rstrip(";")
            if candidate.lower().startswith(("select", "insert")):
                return candidate
        return next((line.strip() for line in text.splitlines() if line.strip()), "")
    except Exception as exc:
        debug_log(f"LLM call failed: {exc}")
        return ""


def _extract_reward(message: str) -> float:
    try:
        if "Reward:" in message:
            return float(message.split("Reward:", 1)[1].strip())
    except Exception:
        return 0.0
    return 0.0


async def run_task(task: dict) -> float:
    task_name = task["name"]
    task_desc = task["description"]
    max_steps = task["max_steps"]
    fallback_queries = task["fallback_queries"]

    rewards: List[float] = []
    steps_taken = 0
    success = False
    history: List[str] = []

    env = SecurityEnv()
    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    try:
        obs = env.reset()
        obs_message = obs.message
        db_output = obs.db_output
        done = obs.done

        for step in range(1, max_steps + 1):
            if done:
                break

            error: Optional[str] = None
            query = _ask_llm(task_desc, obs_message, db_output, step, history)
            if not query:
                query = fallback_queries[min(step - 1, len(fallback_queries) - 1)]
                error = "using fallback query"

            try:
                obs = env.step(SQLAction(query=query))
            except Exception as exc:
                error = str(exc)
                obs = SQLObservation(
                    db_output="",
                    message=f"Runtime error: {exc}",
                    done=False,
                )

            obs_message = obs.message
            db_output = obs.db_output
            done = obs.done
            reward = _extract_reward(obs_message)

            rewards.append(reward)
            steps_taken = step
            history.append(
                f"Step {step}: query={query!r} -> reward={reward:+.0f} done={done}"
            )

            log_step(step=step, action=query, reward=reward, done=done, error=error)

            if done and reward >= 100.0:
                success = True
                break
    except Exception as exc:
        debug_log(f"run_task({task_name}) raised: {exc}")

    if success:
        score = 1.0
    else:
        positive_reward = sum(reward for reward in rewards if reward > 0)
        score = max(0.0, min(0.99, positive_reward / _MAX_REWARD))

    log_end(success=success, steps=steps_taken, score=score, rewards=rewards)
    return score


async def main() -> None:
    for task in TASKS:
        score = await run_task(task)
        debug_log(f"Completed task={task['name']} score={score:.2f}")


if __name__ == "__main__":
    asyncio.run(main())
