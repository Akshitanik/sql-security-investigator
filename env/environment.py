from .models import SQLAction, SQLObservation
from .scenarios import init_db, HACKER_IP
from .reward import calculate_reward


class SecurityEnv:

    def __init__(self):
        self.conn = None
        self.steps = 0
        self.max_steps = 10
        self.last_observation = SQLObservation(
            db_output="",
            message="Environment not initialized. Call reset().",
            done=False,
        )

    def reset(self):
        self.conn = init_db()
        self.steps = 0

        self.last_observation = SQLObservation(
            db_output="",
            message="Database initialized. Investigate logs.",
            done=False
        )
        return self.last_observation

    def state(self):
        if self.conn is None:
            self.reset()
        return self.last_observation

    def step(self, action: SQLAction):
        self.steps += 1
        cursor = self.conn.cursor()

        try:
            query = action.query.strip().lower()

            # Safety: allow only SELECT and INSERT
            if not (query.startswith("select") or query.startswith("insert")):
                self.last_observation = SQLObservation(
                    db_output="",
                    message="Only SELECT and INSERT allowed",
                    done=False
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
                done=False
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
            done=done
        )
        return self.last_observation