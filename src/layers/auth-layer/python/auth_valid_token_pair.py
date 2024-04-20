import logging

LOGGER = logging.getLogger()


class AuthValidTokenPairDb:
    def __init__(self, table):
        self.table = table

    def get(self, refresh_token_jti: str) -> dict:
        db_resp = self.table.get_item(
            Key={"pk": f"RefreshToken#{refresh_token_jti}"},
            ProjectionExpression="access_token_jti,expired_at",
        )
        LOGGER.debug("db_resp: %s", db_resp)

        return db_resp.get("Item", {})
