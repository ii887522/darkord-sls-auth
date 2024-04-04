class CommonException(Exception):
    def __init__(self, code: int, msg=""):
        self.code = code
        self.msg = msg
        super().__init__(code, msg)
