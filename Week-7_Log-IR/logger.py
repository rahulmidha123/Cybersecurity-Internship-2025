import logging
from pathlib import Path

logs_dir = Path(__file__).resolve().parents[1] / "logs"
logs_dir.mkdir(exist_ok=True)
log_path = logs_dir / "suspicious.log"

logger = logging.getLogger("AKD")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_path, encoding='utf-8')
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def log_suspicious(message):
    logger.warning(message)
