import logging
from passlib.context import CryptContext
from config import config

logs_config = config["logs"]
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def initiate_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logs_config["level"])
    console_stream = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)-30s "
                                  "%(levelname)-10s "
                                  "%(filename)-25s"
                                  "L#:%(lineno)-20s"
                                  "%(message)s")
    console_stream.setFormatter(formatter)
    logger.addHandler(console_stream)
    return logger


def compare_passwords(plain_password: str, hashed_password: str) -> bool:
    comparison_result = pwd_context.verify(plain_password, hashed_password)
    return comparison_result


def get_password_hash(password: str) -> str:
    hashed_password = pwd_context.hash(password)
    return hashed_password
