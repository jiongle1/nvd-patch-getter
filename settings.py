import logging
import json
import sys

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.DEBUG)

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

logger.addHandler(console_handler)
logger.addHandler(file_handler)


global_config = None

def load_config(crucial_keys) -> dict:
    global global_config
    try:
        if global_config is None:
            with open('config.json', 'r') as file:
                global_config = json.load(file)

            for key in crucial_keys:
                if key not in global_config:
                    raise ValueError(f"{key} not found in config.json, exiting now...")
            return global_config
    except FileNotFoundError:
        logger.error("config.json file not found")
        sys.exit(1)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

def get_config():
    crucial_keys = ['apiKey']
    if global_config is None:
        load_config(crucial_keys)
    return global_config