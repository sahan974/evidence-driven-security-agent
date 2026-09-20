class ProfilePresenter:
    def public_view(self, user: dict) -> dict:
        return {
            "id": user["id"],
            "display_name": user["display_name"],
        }
