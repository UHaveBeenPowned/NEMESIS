import logging
import os
from pathlib import Path

LOG_FILE: str = "NEMESIS.log";
NEMESIS_LOG_FOLDER = Path(os.environ["USERPROFILE"]) / "Desktop" / "NEMESIS"
NEMESIS_LOG_FOLDER.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=NEMESIS_LOG_FOLDER/LOG_FILE,
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
);

def log_info(msg):
    print(msg);
    logging.info(msg);

def log_error(msg):
    print(msg);
    logging.error(msg);