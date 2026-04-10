from .scenarios import HACKER_IP


def calculate_reward(conn, last_query: str):
    cursor = conn.cursor()
    lowered = last_query.lower()
    normalized = " ".join(lowered.split())

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
    if normalized.startswith("select"):
        cursor.execute(
            "SELECT COUNT(*) FROM access_logs WHERE ip = ? AND status = 'failed'",
            (HACKER_IP,),
        )
        count = cursor.fetchone()[0]

        failed_filter_present = (
            "status='failed'" in normalized
            or "status = 'failed'" in normalized
            or 'status="failed"' in normalized
            or 'status = "failed"' in normalized
        )

        if "group by ip" in normalized and failed_filter_present:
            return 15, False
        if failed_filter_present and count >= 3:
            return 8, False

    # Penalize non-hacker insert actions to discourage random blocking.
    if normalized.startswith("insert") and HACKER_IP not in normalized:
        return -20, False

    # Default small step penalty
    return -2, False
