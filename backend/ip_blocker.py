from db import cursor

def is_blocked(ip):

    query = """
    SELECT * FROM blocked_ips
    WHERE ip_address=%s
    """

    cursor.execute(query, (ip,))

    result = cursor.fetchone()

    return result is not None