import uuid

import jwt


def encode(
    key: str,
    type: str,
    exp: int,
    id="",
    sub="",
    name="",
    aud="",
    dest="",
    roles: list[str] = [],
    orig="",
) -> str:
    payload = {"typ": type, "jti": id or str(uuid.uuid4()), "exp": exp}

    if sub:
        payload["sub"] = sub

    if name:
        payload["name"] = name

    if aud:
        payload["aud"] = aud

    if dest:
        payload["dest"] = dest

    if roles:
        payload["roles"] = roles

    if orig:
        payload["orig"] = orig

    return jwt.encode(payload=payload, key=key, algorithm="HS512")
