import logging
from config import config

logs_config = config["logs"]


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
