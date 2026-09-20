from dataclasses import dataclass

from account_service import AccountService


@dataclass(frozen=True)
class AccountSearch:
    username: str


class AccountEndpoint:
    def __init__(self, service: AccountService) -> None:
        self._service = service

    def search(self, connection, request: AccountSearch):
        return self._service.find_account(connection, request.username)


def find_account(connection, username: str):
    endpoint = AccountEndpoint(AccountService())
    return endpoint.search(connection, AccountSearch(username=username))
