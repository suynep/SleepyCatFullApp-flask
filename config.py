import os
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "you-will-never-guess"
    ACCESS_TOKEN_EXPIRES = timedelta(days=1)