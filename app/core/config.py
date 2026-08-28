import os
from dotenv import load_dotenv


load_dotenv()


class Settings:
    APP_NAME = os.getenv(
        "APP_NAME",
        "Hệ thống giám sát bảo mật website bất động sản",
    )

    APP_ENV = os.getenv(
        "APP_ENV",
        "development",
    )

    BACKEND_URL = os.getenv(
        "BACKEND_URL",
        "https://quanghuy-backend.onrender.com",
    )


settings = Settings()