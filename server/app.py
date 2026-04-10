from fastapi import FastAPI
from openenv.core.env_server import create_app
import uvicorn

from env.environment import SecurityEnv
from env.models import SQLAction, SQLObservation

app = FastAPI(title="SQL Security Investigator")
shared_env = SecurityEnv()


def _serialize_observation(observation: SQLObservation) -> dict:
    return observation.model_dump(exclude={"metadata"})


@app.get("/")
def root():
    return {"status": "ok"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/reset")
@app.post("/reset")
def reset():
    return _serialize_observation(shared_env.reset())


@app.get("/state")
def state():
    return _serialize_observation(shared_env.state())


@app.post("/step")
def step(action: SQLAction):
    return _serialize_observation(shared_env.step(action))


openenv_app = create_app(
    SecurityEnv,
    SQLAction,
    SQLObservation,
    env_name="sql-security-investigator",
)

app.mount("/", openenv_app)


def main():
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()
