from openenv.core.env_server import create_app
from env.environment import SecurityEnv
from env.models import SQLAction, SQLObservation

app = create_app(
    SecurityEnv,
    SQLAction,
    SQLObservation,
    env_name="sql-security-investigator",
)

