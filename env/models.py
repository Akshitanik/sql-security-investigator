from pydantic import BaseModel

class SQLAction(BaseModel):
    query: str  # SQL query from agent


class SQLObservation(BaseModel):
    db_output: str   # result from DB
    message: str     # feedback
    done: bool       # episode finished or not
    