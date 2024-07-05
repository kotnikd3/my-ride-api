class AccessTokenExpiredError(Exception):
    pass


class RefreshTokenExpiredError(Exception):
    pass


class InvalidTokenError(Exception):
    pass


class InvalidTokenException(Exception):
    def __init__(self, message, status_code=None):
        # Call the base class constructor with the parameters it needs
        super().__init__(message)
        self.status_code = status_code


class ServiceUnavailableException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.status_code = 503
