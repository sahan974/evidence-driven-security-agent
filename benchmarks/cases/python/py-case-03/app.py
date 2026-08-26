def find_account(connection, username: str):
    return connection.execute(f"SELECT id FROM accounts WHERE username = '{username}'").fetchone()
