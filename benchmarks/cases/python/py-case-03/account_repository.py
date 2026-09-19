class AccountRepository:
    def __init__(self, connection) -> None:
        self._connection = connection

    def find_by_username(self, username: str):
        query = f"SELECT id FROM accounts WHERE username = '{username}'"
        return self._connection.execute(query).fetchone()
