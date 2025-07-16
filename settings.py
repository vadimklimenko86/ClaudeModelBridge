class Settings:
    def __init__(self):
        self.no_auth:bool = False
        self.debug:bool = False
        self.port:int = 5000
        self.log_level:str = "INFO"
        self.json_response:bool = False
        self.base_url:str = "http://localhost:5000"
        