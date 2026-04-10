from .models import SQLAction, SQLObservation
from .scenarios import init_db, HACKER_IP
from .reward import calculate_reward
from openenv.core.env_server.types import EnvironmentMetadata


class SecurityEnv:

    def __init__(self):
        self.conn = None
        self.steps = 0
        self.max_steps = 10
        self.last_observation = SQLObservation(
            db_output="",
            message="Environment not initialized. Call reset().",
            done=False,
            reward=None,
        )

    def reset(self):
        if self.conn is not None:
            self.conn.close()
        self.conn = init_db()
        self.steps = 0

        self.last_observation = SQLObservation(
            db_output="",
            message="Database initialized. Investigate logs.",
            done=False,
            reward=None,
        )
        return self.last_observation

    def state(self):
        if self.conn is None:
            self.reset()
        return self.last_observation

    def get_metadata(self):
        return EnvironmentMetadata(
            name="sql-security-investigator",
            description="AI Agent for SQL-based security forensic analysis and threat neutralization.",
            version="1.0.0",
            readme_content=None,
            author="Akshita",
        )

    async def reset_async(self):
        return self.reset()

    async def state_async(self):
        return self.state()

    def step(self, action: SQLAction):
        if self.conn is None:
            self.reset()

        self.steps += 1
        cursor = self.conn.cursor()

        try:
            query = action.query.strip().lower()

            # Safety: allow only SELECT and INSERT
            if not (query.startswith("select") or query.startswith("insert")):
                self.last_observation = SQLObservation(
                    db_output="",
                    message="Only SELECT and INSERT allowed",
                    done=False,
                    reward=-2,
                )
                return self.last_observation

            cursor.execute(action.query)

            # Fetch output if SELECT
            if query.startswith("select"):
                rows = cursor.fetchall()
                db_output = str(rows)
            else:
                self.conn.commit()
                db_output = "Query executed"

        except Exception as e:
            self.last_observation = SQLObservation(
                db_output="",
                message=f"SQL Error: {str(e)}",
                done=False,
                reward=-2,
            )
            return self.last_observation

        # Calculate reward
        reward, done = calculate_reward(self.conn, action.query)

        # Check step limit
        if self.steps >= self.max_steps:
            done = True

        self.last_observation = SQLObservation(
            db_output=db_output,
            message=f"Reward: {reward}",
            done=done,
            reward=reward,
        )
        return self.last_observation

    async def step_async(self, action: SQLAction):
        return self.step(action)

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None
