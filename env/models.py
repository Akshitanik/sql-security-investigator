from openenv.core.env_server.types import Action, Observation


class SQLAction(Action):
    query: str  # SQL query from agent


class SQLObservation(Observation):
    db_output: str   # result from DB
    message: str     # feedback
