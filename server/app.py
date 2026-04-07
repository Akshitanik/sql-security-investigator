from fastapi import FastAPI
from env.environment import SecurityEnv
from env.models import SQLAction

app = FastAPI(title="SQL Security Investigator API")

# global env instance
env = SecurityEnv()


@app.get("/")
def home():
    return {"message": "SQL Security Investigator Environment Running"}


@app.get("/reset")
def reset():
    obs = env.reset()
    return obs.dict()


@app.post("/reset")
def reset_post():
    obs = env.reset()
    return obs.dict()


@app.get("/state")
def state():
    obs = env.state()
    return obs.dict()


@app.post("/step")
def step(action: SQLAction):
    obs = env.step(action)
    return obs.dict()