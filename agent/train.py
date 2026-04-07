from env.environment import SecurityEnv
from env.models import SQLAction
from .model import QLearningAgent


def train(episodes=50):
    env = SecurityEnv()
    agent = QLearningAgent()

    for episode in range(episodes):
        obs = env.reset()
        total_reward = 0

        print(f"\n--- Episode {episode+1} ---")

        done = False

        while not done:
            action_query = agent.choose_action(obs)
            action = SQLAction(query=action_query)

            next_obs = env.step(action)

            # UPDATE THE DONE FLAG HERE!
            done = next_obs.done  

            # Extract reward from message
            # (Make sure your environment.py actually sends "Reward: 100" format)
            try:
                reward = int(next_obs.message.split(":")[1].strip())
            except:
                reward = -1 # fallback if message format is weird

            agent.update(obs, action_query, reward, next_obs)

            obs = next_obs
            total_reward += reward
        

            print(f"Action: {action_query}")
            print(f"Reward: {reward}")
            print(f"Output: {obs.db_output}")
            print("------")

        print(f"Total Reward: {total_reward}")

    return agent


if __name__ == "__main__":
    trained_agent = train(episodes=30)