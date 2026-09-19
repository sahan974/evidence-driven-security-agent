from account_repository import AccountRepository


class AccountService:
    def find_account(self, connection, username: str):
        normalized = username.strip().lower()
        if not normalized:
            return None
        repository = AccountRepository(connection)
        return repository.find_by_username(normalized)
