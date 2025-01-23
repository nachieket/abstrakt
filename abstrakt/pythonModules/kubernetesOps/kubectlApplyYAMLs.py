import os
import subprocess


class KubectlApplyYAMLs:
  def __init__(self, directory, logger):
    self.directory = directory
    self.logger = logger

  def find_yaml_files(self):
    yaml_files = []
    for root, dirs, files in os.walk(self.directory):
      for file in files:
        if file.endswith(".yaml") or file.endswith(".yml"):
          yaml_files.append(os.path.join(root, file))
    return yaml_files

  def apply_yaml_files(self, logger=None):
    logger = logger or self.logger

    yaml_files = self.find_yaml_files()

    for yaml_file in yaml_files:
      try:
        process = subprocess.run(["kubectl", "apply", "-f", yaml_file], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,check=True, text=True)

        if process.stdout:
          logger.info(process.stdout)

        if process.stderr:
          logger.info(process.stderr)
      except Exception as e:
        logger.info(f"Error applying {yaml_file}: {e}")
