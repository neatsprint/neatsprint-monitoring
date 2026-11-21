from neatsprint_lib.settings import ServiceSettings


class Settings(ServiceSettings):
    service_name: str = "monitoring"
    api_prefix: str = "monitor"


settings = Settings()
