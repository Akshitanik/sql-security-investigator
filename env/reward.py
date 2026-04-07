HACKER_IP = "192.168.1.50"


def calculate_reward(conn, last_query: str):
    cursor = conn.cursor()

    # Check if hacker is blocked
    cursor.execute("SELECT * FROM firewall WHERE blocked_ip = ?", (HACKER_IP,))
    blocked = cursor.fetchone()

    if blocked:
        return 100, True  # success + done

    # Check if agent is exploring correctly
    if "select" in last_query.lower():
        cursor.execute("SELECT COUNT(*) FROM access_logs WHERE ip = ? AND status = 'failed'", (HACKER_IP,))
        count = cursor.fetchone()[0]

        if count > 0:
            return 20, False  # found hacker pattern

    # Default step penalty
    return -1, False