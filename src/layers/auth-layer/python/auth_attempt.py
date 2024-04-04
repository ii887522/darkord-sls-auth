import auth_constants


def get_cond_check_transact_item(
    action: str,
    ip_addr: str,
    max_attempt: int,
    ret_val_on_cond_check_fail="ALL_OLD",
) -> dict:
    return {
        "ConditionCheck": {
            "TableName": auth_constants.AUTH_ATTEMPT_TABLE_NAME,
            "Key": {
                "pk": f"{action.replace('_', ' ').title().replace(' ', '')}#{ip_addr}",
                "sk": "Attempt",
            },
            # Temporarily block the user if they have already made maximum attempts to reduce brute-force attack
            "ConditionExpression": "attribute_not_exists(attempt) or attempt < :ma",
            "ExpressionAttributeValues": {":ma": max_attempt},
            "ReturnValuesOnConditionCheckFailure": ret_val_on_cond_check_fail,
        },
    }
