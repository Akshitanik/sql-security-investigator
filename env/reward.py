HACKER_IP = "192.168.1.50"


def calculate_reward(conn, last_query: str):
    cursor = conn.cursor()
    lowered = last_query.lower()

    # Any benign block is treated as a critical false positive.
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM firewall
        WHERE blocked_ip IN (
            SELECT DISTINCT ip FROM access_logs WHERE status = 'success'
        )
        """
    )
    benign_blocks = cursor.fetchone()[0]
    if benign_blocks > 0:
        return -60, True

    # Check if hacker is blocked
    cursor.execute("SELECT * FROM firewall WHERE blocked_ip = ?", (HACKER_IP,))
    blocked = cursor.fetchone()

    if blocked:
        return 100, True  # success + done

    # Reward meaningful investigation signals.
    if lowered.startswith("select"):
        cursor.execute(
            "SELECT COUNT(*) FROM access_logs WHERE ip = ? AND status = 'failed'",
            (HACKER_IP,),
        )
        count = cursor.fetchone()[0]

        if "group by ip" in lowered and "status='failed'" in lowered:
            return 15, False
        if "status='failed'" in lowered and count >= 3:
            return 8, False

    # Penalize non-hacker insert actions to discourage random blocking.
    if lowered.startswith("insert") and HACKER_IP not in lowered:
        return -20, False

    # Default small step penalty
    return -2, False