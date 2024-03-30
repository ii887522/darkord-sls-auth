class ApiException(Exception):
    def __init__(self, code: int, msg=""):
        super().__init__(code, msg)
        self.code = code
        self.msg = msg
