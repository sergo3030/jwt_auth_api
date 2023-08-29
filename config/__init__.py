from envyaml import EnvYAML
import os


env = os.getenv('ENV_VAR')
if env is None:
    env = "dev"

config_file = f"config_{env}.yaml"
config = EnvYAML(yaml_file=f"{os.path.dirname(__file__)}/{config_file}")
