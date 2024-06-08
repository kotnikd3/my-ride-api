class AccessTokenExpiredError(Exception):
    pass


class RefreshTokenExpiredError(Exception):
    pass


class InvalidTokenError(Exception):
    pass
