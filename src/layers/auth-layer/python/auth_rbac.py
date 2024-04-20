import logging

LOGGER = logging.getLogger()


class AuthRbacDb:
    def __init__(self, table):
        self.table = table

    def get(self, method: str, path: str) -> dict:
        db_resp = self.table.get_item(
            Key={"pk": f"Route#{method}_{path}", "sk": "Rbac"},
            ProjectionExpression="roles",
        )
        LOGGER.debug("db_resp: %s", db_resp)

        return db_resp.get("Item", {})
