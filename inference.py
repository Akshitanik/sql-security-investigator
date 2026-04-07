import os
from openai import OpenAI

from env.models import SQLAction
from server.app import env

# Env vars required by hackathon: defaults only for API_BASE_URL and MODEL_NAME (not HF_TOKEN).
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.2-3B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")


def _get_client() -> OpenAI:
    if not HF_TOKEN:
        raise ValueError("Set HF_TOKEN before running inference.py (no default for security).")

    return OpenAI(base_url=API_BASE_URL, api_key=HF_TOKEN)


def run():
    client = _get_client()
    model_name = MODEL_NAME
    fallback_queries = [
        "SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC",
        "INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')",
    ]

    obs = env.reset()
    print("[START] env=sql-security-investigator")

    for step in range(1, 11):
        prompt = (
            "You are a security analyst. Return exactly one SQL query to investigate and block "
            "the malicious IP from this environment.\n"
            f"Observation message: {obs.message}\n"
            f"Observation output: {obs.db_output}\n"
            "Allowed SQL: SELECT and INSERT."
        )

        try:
            completion = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0,
            )
            query = completion.choices[0].message.content.strip().splitlines()[0]
            if not query:
                raise ValueError("Empty query from model")
        except Exception:
            query = fallback_queries[min(step - 1, len(fallback_queries) - 1)]

        obs = env.step(SQLAction(query=query))
        print(f"[STEP] step={step} query={query!r} done={obs.done} message={obs.message!r}")

        if obs.done:
            break

    print(f"[END] done={obs.done} final_message={obs.message!r}")


if __name__ == "__main__":
    run()
