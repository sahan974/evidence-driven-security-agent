from dataclasses import dataclass

from profile_presenter import ProfilePresenter


@dataclass(frozen=True)
class ProfileRequest:
    user: dict


class ProfileEndpoint:
    def __init__(self, presenter: ProfilePresenter) -> None:
        self._presenter = presenter

    def get(self, request: ProfileRequest) -> dict:
        return self._presenter.public_view(request.user)


def public_profile(user: dict) -> dict:
    return ProfileEndpoint(ProfilePresenter()).get(ProfileRequest(user))
