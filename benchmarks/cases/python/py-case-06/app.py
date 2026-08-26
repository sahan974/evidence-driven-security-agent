def public_profile(user: dict) -> dict:
    return {"id": user["id"], "display_name": user["display_name"]}
