import random


class QLearningAgent:

    def __init__(self):
        self.q_table = {}

        # possible actions
        self.actions = [
            "SELECT * FROM access_logs WHERE status='failed'",
            "SELECT ip, COUNT(*) FROM access_logs WHERE status='failed' GROUP BY ip",
            "INSERT INTO firewall (blocked_ip) VALUES ('192.168.1.50')"
        ]

        # hyperparameters
        self.alpha = 0.1     # learning rate
        self.gamma = 0.9     # discount factor
        self.epsilon = 0.2   # exploration

    def get_state_key(self, observation):
        """
        Convert observation to a simple state representation
        """
        return observation.message  # simple but works

    def choose_action(self, observation):
        state = self.get_state_key(observation)

        # initialize state if new
        if state not in self.q_table:
            self.q_table[state] = [0] * len(self.actions)

        # epsilon-greedy
        if random.random() < self.epsilon:
            return random.choice(self.actions)

        q_values = self.q_table[state]
        max_index = q_values.index(max(q_values))
        return self.actions[max_index]

    def update(self, observation, action, reward, next_observation):
        state = self.get_state_key(observation)
        next_state = self.get_state_key(next_observation)

        # init states
        if state not in self.q_table:
            self.q_table[state] = [0] * len(self.actions)

        if next_state not in self.q_table:
            self.q_table[next_state] = [0] * len(self.actions)

        action_index = self.actions.index(action)

        # Q-learning update
        old_value = self.q_table[state][action_index]
        next_max = max(self.q_table[next_state])

        new_value = old_value + self.alpha * (
            reward + self.gamma * next_max - old_value
        )

        self.q_table[state][action_index] = new_value