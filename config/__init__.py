from envyaml import EnvYAML
import os


environment = os.getenv('ENV_VAR')
if environment is None:
    environment = "dev"
config_file_name = f"config_{environment}.yaml"
config = EnvYAML(yaml_file=f"config/{config_file_name}")
