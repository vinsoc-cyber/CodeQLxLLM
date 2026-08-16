# SafeLoader — only loads YAML primitive types
import yaml


def load_config(path: str):
    with open(path) as f:
        return yaml.safe_load(f)
