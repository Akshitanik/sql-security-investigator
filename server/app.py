from fastapi import FastAPI
from env.environment import SecurityEnv
from env.models import SQLAction

app = FastAPI(title="SQL Security Investigator API")

# global env instance (reset on startup)
env = SecurityEnv()


@app.on_event("startup")
async def startup_event():
    """Auto-reset environment on server start so it's ready immediately."""
    env.reset()


@app.get("/")
def home():
    return {"message": "SQL Security Investigator Environment Running", "status": "ok"}


@app.get("/reset")
def reset_get():
    obs = env.reset()
    return obs.model_dump()


@app.post("/reset")
def reset_post():
    obs = env.reset()
    return obs.model_dump()


@app.get("/state")
def state():
    obs = env.state()
    return obs.model_dump()


@app.post("/step")
def step(action: SQLAction):
    obs = env.step(action)
    return obs.model_dump()