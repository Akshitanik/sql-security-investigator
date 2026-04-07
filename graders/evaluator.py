from env.environment import SecurityEnv
from env.models import SQLAction


class Evaluator:
    """
    Three deterministic tasks:
    - easy: identify suspicious failures
    - medium: identify top failed IP using aggregation
    - hard: block hacker IP and finish episode

    All scores are in [0.0, 1.0] for OpenEnv leaderboard compatibility.
    """

    def evaluate(self):
        env = SecurityEnv()

        easy_score = self.grade_easy(env)
        medium_score = self.grade_medium(env)
        hard_score = self.grade_hard(env)

        success_rate = (easy_score + medium_score + hard_score) / 3.0
        score = success_rate

        return {
            "task_easy": easy_score,
            "task_medium": medium_score,
            "task_hard": hard_score,
            "success_rate": success_rate,
            "score": score,
        }

    def grade_easy(self, env: SecurityEnv) -> float:
        env.reset()
        obs = env.step(SQLAction(query="SELECT * FROM access_logs WHERE status='failed'"))
        return 1.0 if "192.168.1.50" in obs.db_output else 0.0

    def grade_medium(self, env: SecurityEnv) -> float:
        env.reset()
        obs = env.step(
            SQLAction(
                query="SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip ORDER BY COUNT(*) DESC"
            )
        )
        return 1.0 if "192.168.1.50" in obs.db_output else 0.0

    def grade_hard(self, env: SecurityEnv) -> float:
        env.reset()
        env.step(SQLAction(query="SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip"))
        obs = env.step(SQLAction(query="INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')"))
        return 1.0 if obs.done else 0.0


if __name__ == "__main__":
    evaluator = Evaluator()
    results = evaluator.evaluate()

    print("\n" + "=" * 40)
    print("SQL SECURITY INVESTIGATOR EVALUATION")
    print("=" * 40)
    print(f"Task easy:    {results['task_easy']:.2f}")
    print(f"Task medium:  {results['task_medium']:.2f}")
    print(f"Task hard:    {results['task_hard']:.2f}")
    print(f"Success rate: {results['success_rate']:.2f}")
    print(f"Final score:  {results['score']:.2f}")
    print("=" * 40)
