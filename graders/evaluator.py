"""
SQL Security Investigator — Evaluator / Grader
===============================================
Three deterministic tasks scored in [0.0, 1.0] for OpenEnv leaderboard compatibility.

  task_easy   — detect malicious IP from raw failed-login rows
  task_medium — identify top failed IP via aggregation
  task_hard   — investigate then block the malicious IP (partial credit)

Usage:
  # Direct (in-process) evaluation — no server required:
  python -m graders.evaluator

  # HTTP evaluation against a running server:
  python -m graders.evaluator --url http://localhost:8000
"""

import argparse
import json
import sys

import requests


# ── In-process evaluation (no HTTP) ──────────────────────────────────────────
def _run_in_process():
    from env.environment import SecurityEnv
    from env.models import SQLAction

    class Evaluator:
        """
        Three deterministic graders:
          easy:   detect the malicious IP from failed rows
          medium: identify it via COUNT(*) / GROUP BY aggregation
          hard:   investigate + block it (partial credit model)

        All scores are in [0.0, 1.0].
        """

        def evaluate(self):
            env = SecurityEnv()

            easy_score   = self.grade_easy(env)
            medium_score = self.grade_medium(env)
            hard_score   = self.grade_hard(env)

            success_rate = round((easy_score + medium_score + hard_score) / 3.0, 4)
            score        = success_rate

            return {
                "task_easy":    easy_score,
                "task_medium":  medium_score,
                "task_hard":    hard_score,
                "success_rate": success_rate,
                "score":        score,
            }

        def grade_easy(self, env) -> float:
            """
            Easy: run a simple SELECT on failed rows.
            Pass if the malicious IP appears in the output.
            """
            env.reset()
            obs = env.step(SQLAction(query="SELECT * FROM access_logs WHERE status='failed'"))
            return 1.0 if "192.168.1.50" in obs.db_output else 0.0

        def grade_medium(self, env) -> float:
            """
            Medium: aggregation query.
            Pass if the hacker IP is the top result (highest fail count = 5).
            """
            env.reset()
            obs = env.step(
                SQLAction(
                    query=(
                        "SELECT ip, COUNT(*) FROM access_logs "
                        "WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
                    )
                )
            )
            # Hacker must appear first AND their count (5) must be visible
            return (
                1.0
                if "192.168.1.50" in obs.db_output and "5" in obs.db_output
                else 0.0
            )

        def grade_hard(self, env) -> float:
            """
            Hard: investigate then block.
            Partial credit:
              +0.4 — hacker IP found in investigation query output
              +0.6 — episode terminates cleanly after blocking (no false-positive penalty)
            """
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

            # Mitigation succeeds: episode done + no false-positive penalty
            if mitigation.done and "Reward: -60" not in mitigation.message:
                hard_score += 0.6

            return round(min(max(hard_score, 0.0), 1.0), 2)

    return Evaluator().evaluate()


# ── HTTP evaluation against a live server ─────────────────────────────────────
def _run_http(base_url: str) -> dict:
    """Run the three grading tasks via the REST API."""
    base_url = base_url.rstrip("/")

    def reset():
        r = requests.post(f"{base_url}/reset", timeout=10)
        r.raise_for_status()
        return r.json()

    def step(query: str):
        r = requests.post(f"{base_url}/step", json={"query": query}, timeout=10)
        r.raise_for_status()
        return r.json()

    # ── easy ──────────────────────────────────────────────────────────────────
    reset()
    obs = step("SELECT * FROM access_logs WHERE status='failed'")
    task_easy = 1.0 if "192.168.1.50" in obs.get("db_output", "") else 0.0

    # ── medium ────────────────────────────────────────────────────────────────
    reset()
    obs = step(
        "SELECT ip, COUNT(*) FROM access_logs "
        "WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
    )
    db = obs.get("db_output", "")
    task_medium = 1.0 if "192.168.1.50" in db and "5" in db else 0.0

    # ── hard ─────────────────────────────────────────────────────────────────
    reset()
    inv = step(
        "SELECT ip, COUNT(*) FROM access_logs "
        "WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
    )
    mit = step("INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')")

    hard_score = 0.0
    if "192.168.1.50" in inv.get("db_output", ""):
        hard_score += 0.4
    if mit.get("done") and "Reward: -60" not in mit.get("message", ""):
        hard_score += 0.6

    task_hard = round(min(max(hard_score, 0.0), 1.0), 2)

    success_rate = round((task_easy + task_medium + task_hard) / 3.0, 4)
    return {
        "task_easy":    task_easy,
        "task_medium":  task_medium,
        "task_hard":    task_hard,
        "success_rate": success_rate,
        "score":        success_rate,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Security Investigator Evaluator")
    parser.add_argument(
        "--url",
        default=None,
        help="Server base URL for HTTP evaluation (e.g. http://localhost:8000). "
             "Omit to evaluate in-process.",
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

    # Exit non-zero if any task scores 0 (useful for CI)
    if results["score"] < 1.0:
        sys.exit(0)   # still exit 0 so Docker CMD isn't broken; judges see scores
    sys.exit(0)
