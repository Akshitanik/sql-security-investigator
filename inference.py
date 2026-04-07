import os
from openai import OpenAI

from env.models import SQLAction
from server.app import env


def _get_client() -> OpenAI:
    api_base_url = os.getenv("API_BASE_URL")
    model_name = os.getenv("MODEL_NAME")
    hf_token = os.getenv("HF_TOKEN")

    if not api_base_url or not model_name or not hf_token:
        raise ValueError("Set API_BASE_URL, MODEL_NAME, and HF_TOKEN before running inference.py")

    # OpenAI-compatible client required by hackathon instructions.
    return OpenAI(base_url=api_base_url, api_key=hf_token)


def run():
    client = _get_client()
    model_name = os.getenv("MODEL_NAME")
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
