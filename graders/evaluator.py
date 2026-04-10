"""
SQL Security Investigator evaluator / grader.

Task-level scores are intentionally kept strictly inside (0, 1) because the
hackathon validator rejects exact 0.0 and 1.0 values.
"""

import argparse
import sys

import requests


def _strict_score(value: float) -> float:
    """Clamp scores into the open interval (0, 1)."""
    return round(min(max(value, 0.01), 0.99), 2)


def _run_in_process():
    from env.environment import SecurityEnv
    from env.models import SQLAction

    class Evaluator:
        def evaluate(self):
            env = SecurityEnv()

            easy_score = self.grade_easy(env)
            medium_score = self.grade_medium(env)
            hard_score = self.grade_hard(env)

            success_rate = round((easy_score + medium_score + hard_score) / 3.0, 4)
            score = round(success_rate, 4)

            return {
                "task_easy": easy_score,
                "task_medium": medium_score,
                "task_hard": hard_score,
                "success_rate": success_rate,
                "score": score,
            }

        def grade_easy(self, env) -> float:
            env.reset()
            obs = env.step(SQLAction(query="SELECT * FROM access_logs WHERE status='failed'"))
            return _strict_score(0.99 if "192.168.1.50" in obs.db_output else 0.01)

        def grade_medium(self, env) -> float:
            env.reset()
            obs = env.step(
                SQLAction(
                    query=(
                        "SELECT ip, COUNT(*) FROM access_logs "
                        "WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
                    )
                )
            )
            passed = "192.168.1.50" in obs.db_output and "5" in obs.db_output
            return _strict_score(0.99 if passed else 0.01)

        def grade_hard(self, env) -> float:
            env.reset()
            investigation = env.step(
                SQLAction(
                    query=(
                        "SELECT ip, COUNT(*) FROM access_logs "
                        "WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
                    )
                )
            )
            mitigation = env.step(
                SQLAction(query="INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')")
            )

            hard_score = 0.0
            if "192.168.1.50" in investigation.db_output:
                hard_score += 0.4
            if mitigation.done and "Reward: -60" not in mitigation.message:
                hard_score += 0.6

            return _strict_score(hard_score)

    return Evaluator().evaluate()


def _run_http(base_url: str) -> dict:
    """Run the three grading tasks via the REST API."""
    base_url = base_url.rstrip("/")

    def reset():
        response = requests.post(f"{base_url}/reset", timeout=10)
        response.raise_for_status()
        return response.json()

    def step(query: str):
        response = requests.post(f"{base_url}/step", json={"query": query}, timeout=10)
        response.raise_for_status()
        return response.json()

    reset()
    obs = step("SELECT * FROM access_logs WHERE status='failed'")
    task_easy = _strict_score(0.99 if "192.168.1.50" in obs.get("db_output", "") else 0.01)

    reset()
    obs = step(
        "SELECT ip, COUNT(*) FROM access_logs "
        "WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
    )
    db_output = obs.get("db_output", "")
    task_medium = _strict_score(0.99 if "192.168.1.50" in db_output and "5" in db_output else 0.01)

    reset()
    investigation = step(
        "SELECT ip, COUNT(*) FROM access_logs "
        "WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
    )
    mitigation = step("INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')")

    hard_score = 0.0
    if "192.168.1.50" in investigation.get("db_output", ""):
        hard_score += 0.4
    if mitigation.get("done") and "Reward: -60" not in mitigation.get("message", ""):
        hard_score += 0.6
    task_hard = _strict_score(hard_score)

    success_rate = round((task_easy + task_medium + task_hard) / 3.0, 4)
    return {
        "task_easy": task_easy,
        "task_medium": task_medium,
        "task_hard": task_hard,
        "success_rate": success_rate,
        "score": success_rate,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Security Investigator Evaluator")
    parser.add_argument(
        "--url",
        default=None,
        help="Server base URL for HTTP evaluation (e.g. http://localhost:8000). Omit to evaluate in-process.",
    )
    args = parser.parse_args()

    if args.url:
        print(f"Evaluating via HTTP against {args.url} ...\n")
        results = _run_http(args.url)
    else:
        print("Evaluating in-process ...\n")
        results = _run_in_process()

    print("=" * 40)
    print("SQL SECURITY INVESTIGATOR EVALUATION")
    print("=" * 40)
    print(f"Task easy:    {results['task_easy']:.2f}")
    print(f"Task medium:  {results['task_medium']:.2f}")
    print(f"Task hard:    {results['task_hard']:.2f}")
    print(f"Success rate: {results['success_rate']:.2f}")
    print(f"Final score:  {results['score']:.2f}")
    print("=" * 40)

    sys.exit(0)
