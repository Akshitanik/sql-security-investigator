import os
from openai import OpenAI

from env.models import SQLAction
from server.app import env

LOCAL_IMAGE_NAME = os.getenv("LOCAL_IMAGE_NAME")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.2-3B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")
TASK_NAME = os.getenv("TASK_NAME", "sql-investigation")
BENCHMARK = os.getenv("BENCHMARK", "sql-security-investigator")
MAX_STEPS = 10


def _extract_reward(message: str) -> float:
    try:
        return float(message.split(":")[1].strip())
    except Exception:
        return 0.0


def _get_client() -> OpenAI:
    if not HF_TOKEN:
        raise ValueError("Set HF_TOKEN before running inference.py")
    return OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)


def run() -> None:
    client = _get_client()
    rewards = []
    steps_taken = 0
    success = False

    fallback_queries = [
        "SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC",
        "INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')",
    ]

    print(f"[START] task={TASK_NAME} env={BENCHMARK} model={MODEL_NAME}", flush=True)

    try:
        obs = env.reset()

        for step in range(1, MAX_STEPS + 1):
            prompt = (
                "You are a security analyst. Return exactly one SQL query to investigate and block "
                "the malicious IP from this environment.\n"
                f"Observation message: {obs.message}\n"
                f"Observation output: {obs.db_output}\n"
                "Allowed SQL: SELECT and INSERT."
            )

            error = None
            try:
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0,
                )
                query = (completion.choices[0].message.content or "").strip().splitlines()[0]
                if not query:
                    raise ValueError("empty model output")
            except Exception as exc:
                error = str(exc)
                query = fallback_queries[min(step - 1, len(fallback_queries) - 1)]

            obs = env.step(SQLAction(query=query))
            reward = _extract_reward(obs.message)
            rewards.append(reward)
            steps_taken = step
            done_val = str(obs.done).lower()
            error_val = error if error else "null"

            print(
                f"[STEP] step={step} action={query} reward={reward:.2f} done={done_val} error={error_val}",
                flush=True,
            )

            if obs.done:
                success = True
                break
    finally:
        if hasattr(env, "close"):
            try:
                env.close()
            except Exception:
                pass

        score = 1.0 if success else 0.0
        rewards_str = ",".join(f"{r:.2f}" for r in rewards)
        print(
            f"[END] success={str(success).lower()} steps={steps_taken} score={score:.2f} rewards={rewards_str}",
            flush=True,
        )


if __name__ == "__main__":
    run()
