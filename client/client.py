import requests

BASE_URL = "http://127.0.0.1:8000"


def main():
    # Reset env and print initial observation
    res = requests.get(f"{BASE_URL}/reset", timeout=10)
    res.raise_for_status()
    obs = res.json()
    print("Initial observation:", obs)

    while True:
        action = input("SQL action (or 'exit'): ").strip()
        if action.lower() == "exit":
            break

        # API expects JSON body matching SQLAction model: {"query": "..."}
        res = requests.post(
            f"{BASE_URL}/step",
            json={"query": action},
            timeout=10,
        )
        res.raise_for_status()
        obs = res.json()
        print(obs)

        if obs.get("done"):
            print("Episode finished. Resetting...")
            res = requests.get(f"{BASE_URL}/reset", timeout=10)
            res.raise_for_status()
            print(res.json())


if __name__ == "__main__":
    main()